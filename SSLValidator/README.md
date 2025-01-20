# SSL/TLS Certificate Validator

Un outil pour valider les certificats SSL/TLS des sites web et vérifier leur configuration de sécurité.

## Fonctionnalités

- Validation des certificats SSL/TLS
- Vérification de la date de validité
- Vérification du nom d'hôte
- Analyse des protocoles supportés
- Détection des configurations faibles
- Support des formats JSON et texte
- Vérification complète de la chaîne de certificats

## Installation

1. Cloner le dépôt
2. Installer les dépendances :
```bash
pip install -r requirements.txt
```

## Utilisation

### Validation simple

```bash
python ssl_validator.py example.com
```

### Spécifier un port différent

```bash
python ssl_validator.py example.com --port 8443
```

### Sortie JSON

```bash
python ssl_validator.py example.com --json
```

## Informations vérifiées

- Validité du certificat
- Dates d'expiration
- Correspondance du nom d'hôte
- Algorithme de signature
- Taille de la clé
- Protocoles supportés
- Suites de chiffrement
- Extensions du certificat
- Chaîne de certification

## Codes de retour

- 0 : Certificat valide
- 1 : Certificat invalide ou erreur

## Exemple de sortie

```
Certificate Information:
----------------------
Subject: {'commonName': 'example.com'}
Issuer: {'commonName': 'DigiCert SHA2 Secure Server CA'}
Version: 3
Serial Number: 12345678
Valid From: 2023-01-17 00:00:00
Valid Until: 2024-01-17 23:59:59
Subject Alternative Names: example.com, www.example.com
Signature Algorithm: sha256WithRSAEncryption
Public Key Size: 2048 bits
Valid: Yes

Validation Errors:
----------------
None
```

## Sécurité

L'outil vérifie :
- Protocoles SSL/TLS obsolètes
- Suites de chiffrement faibles
- Tailles de clés insuffisantes
- Algorithmes de signature déconseillés
- Configuration du certificat

## Tests

Pour exécuter les tests :
```bash
python test_validator.py
```

## Dépendances

- Python 3.7+
- cryptography
- pyOpenSSL
