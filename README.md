# multi-protect

Outil de chiffrement multi-destinataires en ligne de commande, développé dans le cadre du Mastère Spécialisé en Sécurité des Systèmes d'Information (MS-SIS).

Il protège un fichier en **confidentialité** et en **intégrité** pour N destinataires simultanément. Chaque destinataire légitime peut déprotéger le fichier avec sa propre clé privée ; un destinataire non légitime ne peut rien en faire.

## Principe cryptographique
Le schéma repose sur du **chiffrement hybride** : un chiffrement symétrique rapide pour les données, et un chiffrement asymétrique pour distribuer la clé de session à chaque destinataire.
### 1. Génération de la clé de session
À chaque chiffrement, deux valeurs sont tirées aléatoirement :
- `Kc` — clé de session `AES-256` (32 octets)
- `IV` — vecteur d'initialisation `AES-CBC` (16 octets)

Ces valeurs ne sont jamais réutilisées et ne transitent jamais en clair.

### 2. Chiffrement des données (confidentialité)
Le fichier d'entrée est chiffré chunk par chunk via **`AES-256-CBC`** avec `Kc` et `IV`. Le traitement en flux permet de gérer des fichiers volumineux sans les charger entièrement en mémoire.
### 3. Distribution de la clé de session (multi-destinataires)

Pour chaque destinataire `Di`, `Kc || IV` est chiffré avec sa clé publique `RSA` via **`PKCS#1 OAEP`** :

```python
def get_Wkc_iv(kc: bytes, iv: bytes, public_key_dest: bytes) -> bytes :
    kc_iv = kc + iv
    cipher = PKCS1_OAEP.new(public_key_dest)
    return cipher.encrypt(kc_iv)
```

Chaque destinataire est le seul à pouvoir déchiffrer son propre `W(Kc||IV)` avec sa clé privée. Les autres destinataires ne peuvent pas accéder à cette valeur.

Pour permettre à chaque destinataire de retrouver son bloc dans la structure sans révéler son identité directement, chaque bloc est indexé par le **`SHA-256` de sa clé publique**.
### 4. Signature (intégrité)

Une fois la structure et les données chiffrées assemblées, l'émetteur calcule une signature **`RSA-PSS`** avec sa clé privée `KprivE` sur l'ensemble `structure || cipher data`. Cela garantit que ni la structure ni le contenu n'ont été altérés, et authentifie l'émetteur auprès des destinataires.
## Format du fichier de sortie
```
0x00 | SHA256(KpubDestinataire1) | RSA_OAEP(KpubDestinataire1, Kc||IV) | ... | 0x00 | SHA256(KpubDestinataireN) | RSA_OAEP(KpubDestinataireN, Kc||IV) | 0x01 | données chiffrées (AES-256-CBC) | signature RSA-PSS
```

- `0x00` marque le début d'un bloc destinataire, `0x01` marque la fin de la structure
- Chaque bloc destinataire fait **1 + 32 + 256 octets** (marqueur + hash `SHA-256` + `RSA-2048` chiffré)
- La signature porte sur l'ensemble : structure + données chiffrées
## Prérequis
```bash
pip install pycryptodome
```

## Génération des clés

Chaque participant génère deux bi-clés `RSA-2048` : une pour le chiffrement, une pour la signature.
```bash
# Clé de chiffrement
openssl genrsa 2048 > my_ciph_priv.pem
openssl rsa -in my_ciph_priv.pem -pubout > my_ciph_pub.pem

# Clé de signature
openssl genrsa 2048 > my_sign_priv.pem
openssl rsa -in my_sign_priv.pem -pubout > my_sign_pub.pem
```

## Utilisation

### Protéger un fichier (l'émetteur)
```bash
python multi_protect.py -e <fichier_entree> <fichier_sortie> <ma_cle_sign_priv.pem> <dest1_ciph_pub.pem> [dest2_ciph_pub.pem ...]
```

Retourne `0` si OK, `1` en cas d'erreur.

### Déprotéger un fichier (le destinataire)
```bash
python multi_protect.py -d <fichier_entree> <fichier_sortie> <ma_cle_ciph_priv.pem> <ma_cle_ciph_pub.pem> <emetteur_sign_pub.pem>
```

Retourne `0` si OK, `1` en cas d'erreur.

## Exemple
```bash
# Alice protège secret.pdf pour Bob et Charlie
python multi_protect.py -e secret.pdf secret alice_sign_priv.pem bob_ciph_pub.pem charlie_ciph_pub.pem

# Bob déprotège le fichier
python multi_protect.py -d secret secret_recovered.pdf bob_ciph_priv.pem bob_ciph_pub.pem alice_sign_pub.pem
```

## Stack technique

| Composant               | Technologie              |
| ----------------------- | ------------------------ |
| Chiffrement symétrique  | `AES-256-CBC`            |
| Chiffrement asymétrique | `RSA-2048` `PKCS#1 OAEP` |
| Signature               | `RSA-2048` `PKCS#1 PSS`  |
| Hachage                 | `SHA-256`                |
| Librairie               | *pycryptodome*           |
| Langage                 | *Python 3.12*            |
