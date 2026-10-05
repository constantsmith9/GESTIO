# Backend Sécurisé SaaSPay & Webhook pour GESTIO

Ce backend implémente le cycle complet d'encaissement SaaSPay sans aucune simulation :
1. **Création sécurisée de sessions de paiement** avec la clé secrète `sk_live_...` (stockée sur le serveur uniquement).
2. **Réception et vérification cryptographique (HMAC-SHA256)** des notifications Webhook de SaaSPay.
3. **Mise à jour stricte de la base de données** : aucun utilisateur ne peut passer "abonné" sans confirmation réelle du Webhook.
4. **Endpoint de vérification en lecture seule** pour l'application Android mobile.

---

## 1. Liste des Variables d'Environnement

À configurer dans votre serveur (Render, Railway, Firebase ou fichier `.env`) :

| Variable | Description | Exemple |
| :--- | :--- | :--- |
| `PORT` | Port d'écoute HTTP du serveur | `3000` |
| `SAASPAY_SECRET_KEY` | Clé secrète de production ou test SaaSPay | Valeur privée du tableau de bord |
| `SAASPAY_WEBHOOK_SECRET` | Secret de signature fourni par SaaSPay | Valeur privée du tableau de bord |
| `SAASPAY_API_BASE_URL` | URL de base de l'API SaaSPay | `https://api.saaspay.app/v1` |
| `SUBSCRIPTIONS_FILE` | Fichier JSON sur un volume persistant | `/var/data/subscriptions.json` |
| `APP_SUCCESS_URL` | URL de retour après paiement validé | `https://gestio.app/success` |
| `APP_CANCEL_URL` | URL de retour en cas d'annulation | `https://gestio.app/cancel` |

Le serveur refuse de démarrer si `SAASPAY_SECRET_KEY` ou `SAASPAY_WEBHOOK_SECRET` est absent. Ne copiez jamais de vraies clés dans le dépôt ni dans l'application Android.

---

## 2. URL du Webhook à Renseigner dans le Tableau de Bord SaaSPay

Dans votre compte marchand SaaSPay (Section **Développeurs > Webhooks**) :
* **URL du Webhook :** `https://votre-backend.onrender.com/api/webhook/saaspay`
* **Événements à écouter :**
  - `payment.success` (ou `charge.completed` / `transaction.paid`)
  - `payment.failed`
  - `subscription.canceled`
* **Secret :** Copiez le secret fourni par SaaSPay et collez-le dans `SAASPAY_WEBHOOK_SECRET`.

---

## 3. Déploiement sur Render depuis GitHub

Le dépôt inclut un Blueprint `render.yaml` à sa racine. Il configure `app/backend`, `npm ci`, `npm start`, le contrôle de santé `/health` et un disque persistant monté sur `/var/data`. Le disque nécessite une instance Render payante; vérifiez le tarif avant de confirmer la création du service.

1. Poussez le dépôt complet sur GitHub.
2. Dans Render, choisissez **New + > Blueprint** et reliez ce dépôt.
3. Vérifiez le plan et le disque proposés par le Blueprint, puis confirmez la création.
4. Saisissez les valeurs privées demandées pour `SAASPAY_SECRET_KEY` et `SAASPAY_WEBHOOK_SECRET`. Ne les ajoutez pas au dépôt.
5. Attendez un déploiement réussi et vérifiez `https://<votre-service>/health` : la réponse doit être HTTP 200 avec `status: ok`.
6. Dans SaaSPay, configurez le webhook `https://<votre-service>/api/webhook/saaspay` et les événements supportés par le fournisseur.
7. Dans les paramètres de l'application Android, saisissez l'URL HTTPS du service et vérifiez la confirmation de l'abonnement.

Si le Blueprint annonce un disque ou un plan payant, c'est nécessaire pour conserver le fichier JSON après un redéploiement. L'ancienne URL Render suspendue ne sera pas réparée par la création du Blueprint : utilisez l'URL du nouveau service ou réactivez l'ancien.

Le webhook refuse toute requête sans signature HMAC-SHA256 valide et n'active qu'une session de paiement existante en attente, avec montant/devise cohérents. L'URL fabriquée en cas d'erreur fournisseur a été supprimée : une panne SaaSPay renvoie maintenant HTTP 502.

---

## 4. Test en Mode Sandbox / Test

Le webhook ne peut plus activer un compte arbitraire : créez d'abord une session de paiement sandbox et gardez son `reference`, son `userId`, son montant et sa devise. Pour tester le webhook, signez exactement le corps JSON envoyé avec `SAASPAY_WEBHOOK_SECRET` :

```bash
BODY='{"event":"payment.success","data":{"id":"tx_test_987654","status":"paid","reference":"<reference-de-session>","amount":5000,"currency":"XOF","metadata":{"user_id":"<userId-de-session>"}}}'
SIGNATURE=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SAASPAY_WEBHOOK_SECRET" | sed 's/^.*= //')
curl -X POST http://localhost:3000/api/webhook/saaspay \
  -H "Content-Type: application/json" \
  -H "x-saaspay-signature: $SIGNATURE" \
  --data-binary "$BODY"

# Vérifier le statut :
curl http://localhost:3000/api/subscription-status/user_123
```
