// =========================================================================
// 1. ROUTE : CRÉATION D'UNE SESSION DE PAIEMENT SÉCURISÉE
// =========================================================================
app.post('/api/create-checkout-session', async (req, res) => {
    try {
        const {
            userId,
            tenantId,
            customerName,
            customerPhone,
            customerEmail,
            plan
        } = req.body;

        if (!userId) {
            return res.status(400).json({
                error: 'userId est requis'
            });
        }

        const selectedPlan = plan || 'MONTHLY_5000';

        const planAmounts = {
            MONTHLY_5000: 5000,
            YEARLY_50000: 50000
        };

        if (!Object.hasOwn(planAmounts, selectedPlan)) {
            return res.status(400).json({
                error: 'Plan invalide'
            });
        }

        const amount = planAmounts[selectedPlan];
        const currency = 'XOF';
        const reference = `GESTIO_${userId}_${Date.now()}`;

        console.log(
            `[Checkout] Création session SaaSPay pour ${userId} - Montant: ${amount} ${currency}`
        );

        try {
            const requestBody = {
                amount,
                currency,
                reference,
                description: `Abonnement GESTIO - ${selectedPlan}`,

                customer_phone: customerPhone || '',
                customer_email:
                    customerEmail || `${userId}@gestio.app`,
                customer_name:
                    customerName || 'Client GESTIO',

                metadata: {
                    user_id: userId,
                    tenant_id: tenantId || 'tenant_main',
                    plan: selectedPlan
                },

                success_url:
                    process.env.APP_SUCCESS_URL ||
                    'https://gestio.app/success',

                cancel_url:
                    process.env.APP_CANCEL_URL ||
                    'https://gestio.app/cancel'
            };

            console.log('[SaaSPay] Envoi de la demande de checkout...');

            const saaspayResponse = await axios.post(
                `${SAASPAY_API_BASE_URL}/checkout-sessions/`,
                requestBody,
                {
                    headers: {
                        Authorization: `Bearer ${SAASPAY_SECRET_KEY}`,
                        'Content-Type': 'application/json',
                        Accept: 'application/json'
                    },
                    timeout: 15000
                }
            );

            // IMPORTANT :
            // On affiche la réponse SaaSPay pour vérifier sa structure.
            console.log(
                '[SaaSPay Response]',
                JSON.stringify(saaspayResponse.data, null, 2)
            );

            const response = saaspayResponse.data || {};

            // SaaSPay peut renvoyer les données directement
            // ou dans une enveloppe "data".
            const data = response.data || response;

            checkoutUrl =
                data.checkout_url ||
                data.checkoutUrl ||
                data.payment_url ||
                data.paymentUrl ||
                data.url;

            externalSessionId =
                data.id ||
                data.session_id ||
                data.sessionId;

            console.log('[SaaSPay] Checkout URL:', checkoutUrl);
            console.log('[SaaSPay] Session ID:', externalSessionId);

        } catch (apiError) {
            console.error(
                '[SaaSPay API Error]',
                apiError.response
                    ? JSON.stringify(apiError.response.data, null, 2)
                    : apiError.message
            );

            return res.status(502).json({
                error:
                    'La passerelle de paiement n’a pas pu créer la session.',
                details:
                    apiError.response?.data || apiError.message
            });
        }

        // Vérification de l'URL renvoyée par SaaSPay
        if (!checkoutUrl) {
            console.error(
                '[SaaSPay] Aucune URL de paiement trouvée dans la réponse.'
            );

            return res.status(502).json({
                error:
                    'SaaSPay n’a pas renvoyé d’URL de paiement.',
                message:
                    'Vérifie les logs [SaaSPay Response] pour voir la réponse exacte.'
            });
        }

        let parsedCheckoutUrl;

        try {
            parsedCheckoutUrl = new URL(checkoutUrl);
        } catch (error) {
            console.error(
                '[SaaSPay] URL de paiement invalide:',
                checkoutUrl
            );

            return res.status(502).json({
                error:
                    'La passerelle a renvoyé une URL de paiement invalide.'
            });
        }

        if (
            parsedCheckoutUrl.protocol !== 'https:' ||
            !externalSessionId
        ) {
            console.error(
                '[SaaSPay] Session incomplète:',
                {
                    checkoutUrl,
                    externalSessionId
                }
            );

            return res.status(502).json({
                error:
                    'La passerelle a renvoyé une session de paiement incomplète.'
            });
        }

        // Enregistrement de la session en attente
        const db = loadDatabase();

        db.subscriptions[userId] = {
            userId,
            tenantId: tenantId || 'tenant_main',
            status: 'PENDING_PAYMENT',
            plan: selectedPlan,
            amount,
            currency,
            reference,
            sessionId: externalSessionId,
            checkoutUrl,
            createdAt: new Date().toISOString(),
            startDate: null,
            endDate: null,
            lastCheckedAt: new Date().toISOString()
        };

        saveDatabase(db);

        console.log(
            `[Checkout] ✓ Session SaaSPay créée pour ${userId}`
        );

        return res.json({
            success: true,
            checkoutUrl,
            sessionId: externalSessionId,
            reference,
            amount,
            currency
        });

    } catch (err) {
        console.error(
            '[Erreur Create Checkout Session]',
            err
        );

        return res.status(500).json({
            error:
                'Erreur serveur lors de la création de la session de paiement'
        });
    }
});
