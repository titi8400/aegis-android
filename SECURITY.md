# Politique de sécurité AEGIS

## État du produit

AEGIS est un prototype Android. La version 0.12 contient un appairage QR hors ligne et une première liaison TCP sur réseau local avec TLS mutuel et épinglage des clés publiques des appareils approuvés. Cette liaison et la messagerie texte ne sont pas encore validées sur deux téléphones physiques. Ne pas utiliser le prototype pour des communications sensibles.

## Fonctions de sécurité présentes

- PIN indépendant de 6 à 12 chiffres, vérifié par PBKDF2-HMAC-SHA256 avec sel.
- Biométrie via AndroidX BiometricPrompt et authentificateur biométrique fort si disponible.
- Verrouillage après 60 secondes d'inactivité et au passage en arrière-plan.
- Temporisation progressive après les échecs de PIN.
- Au dixième échec enregistré, suppression de la clé d'identité de signature locale.
- Identité ECDSA P-256 conservée dans Android Keystore.
- Invitations QR signées et limitées dans le temps, défi-réponse signé et registre anti-rejeu chiffré.
- Appareils de confiance conservés dans le coffre local AES-256-GCM.
- Pour la liaison LAN, certificat TLS temporaire signé avec la clé Android Keystore, authentification mutuelle et vérification par épinglage exact des clés publiques enregistrées.
- Les trames du transport sont limitées à 1 Mio.
- L'historique local par appareil et par pair est conservé dans le coffre AES-256-GCM ; il n'est pas synchronisé automatiquement.
- Les messages texte peuvent porter une date d'expiration locale (1 minute, 1 heure ou 24 heures) ; leur purge dépend de l'exécution de l'application et ne peut pas effacer les copies déjà consultées, exportées ou capturées par le destinataire.
- Les fichiers reçus sont limités à 20 Mio, assemblés en mémoire, vérifiés par SHA-256 puis chiffrés dans le coffre local. Les blocs incomplets ne sont pas repris ; le contenu existe temporairement en mémoire vive pendant le transfert.

## Limites connues

- La liaison réseau est une première implémentation, pas encore validée sur appareils physiques ni auditée.
- La découverte UDP ne sert qu'à trouver des candidats ; elle ne prouve jamais leur identité. La validation TLS par clé épinglée reste obligatoire.
- Le transport actuel fonctionne seulement lorsque les appareils peuvent se joindre directement sur le même réseau IP. Pas de serveur de rendez-vous, de traversée NAT ni de relais.
- Les messages de cette version ne constituent pas encore une messagerie persistante : la couche de stockage des conversations, les accusés, les reprises et les pièces jointes restent à développer.
- Le compteur PIN est stocké dans les préférences privées et n'est pas résistant à un appareil compromis, à l'effacement des données, à une restauration ou à une manipulation de l'horloge.
- La suppression d'une clé ne garantit pas l'effacement physique de toutes les cellules de mémoire flash.
- Un téléphone compromis peut exposer les messages au moment où ils sont affichés ou saisis.
- L'absence de serveur ou relais améliore la décentralisation, mais limite fortement la joignabilité des appareils sur Internet.

## Principes obligatoires

- Aucun secret, clé privée, PIN ou donnée personnelle dans Git.
- Aucun algorithme cryptographique maison pour les communications.
- Toute modification du protocole, des certificats ou du stockage doit être accompagnée de tests et d'une revue.
- Les identités des pairs doivent être comparées par un canal indépendant lors de l'appairage initial.
- Les certificats réseau doivent être acceptés uniquement si leur clé publique correspond à un appareil déjà approuvé localement.
- Les erreurs d'authentification doivent fermer la connexion ; aucun mode dégradé non chiffré n'est autorisé.
- Les limites de connectivité P2P doivent être expliquées à l'utilisateur.
- Un audit indépendant est nécessaire avant toute utilisation réelle.

## Signalement

Ne publiez pas de vulnérabilité exploitable dans une issue publique. Contactez le propriétaire du dépôt par un canal privé avant toute divulgation.
