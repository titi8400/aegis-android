# Politique de sécurité AEGIS

## Périmètre actuel

Le dépôt est un prototype en construction. Il ne doit pas être utilisé pour protéger des communications sensibles. La présence d'Android Keystore dans le code ne signifie pas que l'application complète est sécurisée.

## Signalement

Ne publiez pas de vulnérabilité exploitable dans une issue publique. Pour le moment, contactez le propriétaire du dépôt par un canal privé avant toute divulgation.

## Principes obligatoires

- Aucun secret, clé privée, PIN ou donnée personnelle dans Git.
- Aucun chiffrement maison pour les messages.
- Toute modification cryptographique doit être accompagnée de tests.
- Les clés publiques échangées doivent être authentifiées lors de l'appairage.
- Les états d'échec et les limites P2P doivent être visibles à l'utilisateur.
- Les sauvegardes Android doivent rester désactivées tant qu'une stratégie de sauvegarde chiffrée n'a pas été conçue et testée.
- Une revue indépendante est nécessaire avant toute utilisation réelle.
