# Politique de sécurité AEGIS

## Périmètre actuel

AEGIS est un prototype en construction. L’appairage mutuel QR hors ligne est implémenté, mais aucun transport de messages P2P n’est encore disponible. Ne l'utilisez pas pour protéger des communications sensibles. La présence d'Android Keystore, d'un PIN et de BiometricPrompt ne signifie pas que l'application complète est sécurisée.

## Comportement du prototype

- Le PIN est représenté par un vérificateur PBKDF2-HMAC-SHA256 salé.
- La biométrie passe par AndroidX BiometricPrompt et l'authentificateur biométrique fort de l'appareil.
- L'application se verrouille après 60 secondes sans interaction ou quand elle passe en arrière-plan.
- Les tentatives incorrectes déclenchent une temporisation progressive.
- Au dixième échec enregistré, la clé d'identité de signature locale est supprimée et le verrouillage PIN est réinitialisé.

Cette suppression n'efface pas l'intégralité des données de l'application ni les blocs physiques de mémoire. Le compteur et l'horodatage de verrouillage sont conservés dans les préférences privées de l'application : ils ne résistent pas à un appareil compromis, à l'effacement des données, à une restauration d'état ou à une manipulation de l'horloge. Ce mécanisme est un comportement de prototype, pas une garantie anti-forensique.

## Signalement

Ne publiez pas de vulnérabilité exploitable dans une issue publique. Contactez le propriétaire du dépôt par un canal privé avant toute divulgation.

## Principes obligatoires

- Aucun secret, clé privée, PIN ou donnée personnelle dans Git.
- Aucun chiffrement maison pour les messages.
- Toute modification cryptographique doit être accompagnée de tests unitaires et d’une revue de conception.
- Les invitations QR sont signées ECDSA et limitées à cinq minutes ; seules les clés P-256 sont acceptées.
- Les primitives de défi-réponse signées démontrent la possession des clés, mais ne suffisent pas sans comparaison indépendante des deux empreintes.
- Les invitations déjà consommées sont inscrites dans un registre chiffré local ; une suppression des données ou un retour à un état antérieur du système peut contourner cet historique.
- L’assistant QR peut enregistrer un appareil dans le répertoire chiffré local uniquement après preuve mutuelle et confirmation manuelle de la comparaison des deux empreintes. Cette confirmation reste une déclaration utilisateur, pas une vérification automatique.
- Les clés publiques échangées doivent être authentifiées lors de l'appairage.
- Les états d'échec et les limites P2P doivent être visibles à l'utilisateur.
- Les sauvegardes Android doivent rester désactivées tant qu'une stratégie de sauvegarde chiffrée n'a pas été conçue et testée.
- Une revue indépendante est nécessaire avant toute utilisation réelle.
