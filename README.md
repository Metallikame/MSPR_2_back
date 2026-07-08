# MSPR_2_back — Backend COFRAP (Fonctions OpenFaaS + PostgreSQL)

Fonctions d'authentification et base de données pour le portail COFRAP.

## Structure

```
MSPR_2_back/
├── functions/
│   ├── generate-password/      # Génère mdp 24 chars + QR code
│   │   ├── handler.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── generate-2fa/           # Génère secret TOTP + QR code
│   │   ├── handler.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── authenticate/           # Vérifie login + mdp + code TOTP
│   │   ├── handler.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── change-password/        # Modifie le mdp (auth requise)
│       ├── handler.py
│       ├── requirements.txt
│       └── Dockerfile
├── k8s/
│   └── deployment.yaml         # PostgreSQL + 3 fonctions + Services
├── argocd/
│   └── application.yaml        # Application ArgoCD
└── .github/
    └── workflows/ci.yaml       # Build 3 images → GHCR → update tags
```

## Déploiement

### 1. Enregistrer l'Application dans ArgoCD

```bash
kubectl apply -f argocd/application.yaml
```

Ou via l'UI ArgoCD → **NEW APP** avec :
- **Repository URL** : `https://github.com/Metallikame/MSPR_2_back`
- **Path** : `k8s`
- **Namespace** : `cofrap`
- **Branch** : `main`

### 2. Premier push → tout se déploie

```bash
git add .
git commit -m "feat: initial backend"
git push origin main
```

## API

| Endpoint | Méthode | Corps |
|---|---|---|
| `/function/generate-password` | POST | `{"username": "jean.dupont"}` |
| `/function/generate-2fa` | POST | `{"username": "jean.dupont"}` |
| `/function/authenticate` | POST | `{"username": "...", "password": "...", "totp_code": "123456"}` |
| `/function/change-password` | POST | `{"username": "...", "current_password": "...", "totp_code": "123456", "new_password": "..."}` |

## Base de données

Table `users` créée automatiquement au démarrage de PostgreSQL :

```sql
id | username | password (b64) | mfa (b64) | gendate (unix) | expired (0/1)
```
