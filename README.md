# Backend Paiement Direct SasPay (SoftPay Multi-Pays) & Webhook — GESTIO

Ce backend gère le paiement d'abonnement multi-pays via SasPay (`https://api.saspay.me/api/v1`), la vérification Firebase des utilisateurs, la confirmation OTP et la validation sécurisée des webhooks.

## Variables d'environnement requises

| Variable | Description | Exemple |
| :--- | :--- | :--- |
| `PORT` | Port HTTP du serveur | `3000` |
| `SAASPAY_API_BASE_URL` | URL de base SasPay | `https://api.saspay.me/api/v1` |
| `SAASPAY_SECRET_KEY` | Clé secrète SasPay (`sk_test_...` puis `sk_live_...`) | `sk_test_...` |
| `SAASPAY_WEBHOOK_SECRET` | Secret Webhook fourni par SasPay | `whsec_...` |
| `FIREBASE_PROJECT_ID` | ID du projet Firebase pour vérifier les jetons | `gen-lang-client-0469449992` |
| `APP_SUCCESS_URL` | URL de retour si paiement par lien/carte | `https://votre-site.app/?payment=return` |
| `SUBSCRIPTIONS_FILE` | Fichier JSON persistant | `/var/data/subscriptions.json` |

## Endpoints exposés

- `GET /api/payment-options` : Pays et réseaux Mobile Money actifs chez SasPay (cache 5 min) + option « Carte bancaire » pour les pays non couverts.
- `POST /api/pay-softpay` : Déclenche un paiement direct (`amount: "5000.00"`, `currency: "XOF"`, `fee_charge_mode: "DEDUCTED"`, `Idempotency-Key` UUID) après vérification du jeton Firebase (`userId` extrait du jeton).
- `POST /api/confirm-otp` : Transmet le code SMS à `/payments/{id}/confirm-otp/`.
- `GET /api/payment-status/:paymentId` : Vérifie l'état réel sur `/payments/{paymentId}/verify/` (`PENDING`, `SUCCESS`, `FAILED`).
- `GET /api/subscription-status/:userId` : Statut d'abonnement lu en base.
- `POST /api/webhook/saaspay` : Vérifie `X-Webhook-Timestamp` (<= 5 min) et `X-Webhook-Signature` (`HMAC-SHA256` sur `{timestamp}.{rawBody}` en temps constant), retrouve le paiement par `data.id`, vérifie `charged === 5000` en `XOF`, et revérifie sur `/payments/{id}/verify/` avant d'activer.

## Points à activer dans votre compte SasPay

1. Activez la permission `ALLOW_CLIENT_OVERRIDE` sur votre compte marchand SasPay pour que `fee_charge_mode: "DEDUCTED"` soit appliqué.
2. Configurez l'URL Webhook : `https://<votre-backend>/api/webhook/saaspay` sur les événements `transaction.success` et `transaction.failed`.
3. Testez d'abord avec une clé `sk_test_` (note : vérifiez dans votre espace SasPay si `sk_test_` débite ou simule selon l'opérateur).
