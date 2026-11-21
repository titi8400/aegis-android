# AEGIS — Android

AEGIS est un projet de communication Android de pair à pair (P2P), destiné à la famille et aux proches.

## État du projet

**Version 0.7.0 — prototype en développement.** Le dépôt contient une application Android native Kotlin/Jetpack Compose, un écran de verrouillage PIN/biométrie et une première primitive d'identité avec Android Keystore. Ce n'est pas encore une messagerie opérationnelle ni un produit audité.

## Fonctions présentes dans le prototype

- Configuration d'un PIN indépendant de 6 à 12 chiffres.
- Vérification du PIN par PBKDF2-HMAC-SHA256 avec sel aléatoire.
- Authentification biométrique forte via AndroidX BiometricPrompt lorsque l'appareil la prend en charge.
- Verrouillage après 60 secondes sans interaction et lorsque l'application passe en arrière-plan.
- Temporisation progressive après les échecs de PIN.
- Après 10 échecs comptabilisés, suppression de la clé d'identité Android Keystore et réinitialisation du verrouillage local.
- Création d'une identité de signature ECDSA P-256 dans Android Keystore.
- Création d'invitations d'appairage signées, limitées à cinq minutes.
- Génération et affichage dans l’application d’un QR code à partir de l’invitation signée, valable cinq minutes.
- Scan des QR d'invitation avec CameraX et ML Kit, après autorisation caméra.
- Vérification locale de la signature, rejet des clés EC qui ne sont pas P-256 et calcul de l'empreinte SHA-256 de la clé publique.
- Primitives de défi-réponse ECDSA signées pour démontrer la possession des clés des deux appareils.
- Historique anti-rejeu persistant et chiffré pour les invitations consommées.
- Répertoire local des appareils de confiance, chiffré, conçu pour n’enregistrer un pair qu’après une preuve d’appairage mutuel et la comparaison indépendante des deux empreintes.

**Attention :** la suppression après 10 échecs concerne uniquement l'identité cryptographique de ce prototype. Elle ne constitue pas un effacement garanti de toutes les données du téléphone. Le compteur local est modifiable par un attaquant ayant le contrôle de l'appareil, pouvant effacer les données de l'application ou restaurer un état antérieur. Le coffre de fichiers chiffrés est disponible comme primitive technique, mais il n'est pas encore relié à une base de messages ni à l'interface.

## Décisions d'architecture

- Android natif : Kotlin, Jetpack Compose.
- Communication visée : P2P strict, sans serveur applicatif ni relais.
- Identité : paire de clés créée localement ; seule la clé publique sera partagée via QR code.
- Clé privée : Android Keystore, non exportable par cette API ; protection matérielle selon les capacités de l'appareil.
- Données : coffre local de fichiers AES-256-GCM, clé dédiée non exportable via Android Keystore, fichiers placés dans le répertoire interne exclu des sauvegardes Android.
- Récupération : deuxième appareil de confiance, avec approbation explicite des deux appareils.
- Interface : sombre, technique, accents cyan.

## Appairage QR — première étape

`PairingInviteCodec` crée une invitation temporaire contenant un identifiant d'appareil, la clé publique, un nonce aléatoire et une expiration à cinq minutes. L'ensemble est signé avec la clé privée ECDSA P-256 conservée dans Android Keystore. `PairingQrGenerator` transforme cette invitation en QR code. Le vérificateur contrôle le format, les dates et la signature, puis calcule l'empreinte SHA-256 de la clé publique.

Le QR ne contient aucune clé privée. Cette étape ne constitue pas encore un appairage complet : le scanner, la confirmation utilisateur, la comparaison de l'empreinte par un canal indépendant, la consommation persistante du nonce et le défi-réponse prouvant la possession de la clé privée distante restent à développer. Tant que ces étapes ne sont pas terminées, il ne faut pas considérer un appareil comme authentifié ni lui faire confiance.

## Coffre local chiffré (première primitive)

`EncryptedFileStore` fournit des opérations de dépôt, lecture, suppression et présence d'enregistrements identifiés. Chaque enregistrement est chiffré avec AES-256-GCM ; le nonce est généré par le fournisseur cryptographique Android et l'identifiant du fichier est authentifié comme donnée associée. Le format de fichier est versionné et les écritures passent par un fichier temporaire synchronisé avant renommage. La clé AES est distincte de la clé de signature d'identité.

Cette primitive n'est pas encore une base de données transactionnelle, un système de synchronisation, ni une sauvegarde/récupération. La suppression d'un fichier ou de la clé ne garantit pas l'effacement physique des blocs flash. Il faut encore ajouter des tests sur appareils Android, traiter les erreurs de perte/invalidation de clé et intégrer une couche de dépôt applicative avant d'y stocker des conversations.

## Limites à ne pas masquer

Le P2P strict ne garantit pas qu'une connexion Internet directe soit possible entre deux téléphones. NAT, pare-feu, opérateurs et réseaux Wi-Fi peuvent empêcher la connexion. Sans serveur de découverte ni relais, certains pairs ne pourront pas se joindre à distance.

Le vérificateur PIN utilise les préférences privées de l'application ; ce stockage n'est pas une frontière inviolable. PBKDF2 ralentit les essais hors ligne mais ne rend pas un PIN court impossible à deviner. Le compteur et l'heure de verrouillage ne sont pas résistants à une modification du système.

La suppression de clés ne garantit pas l'effacement physique de chaque bloc de mémoire flash. Un appareil compromis peut exposer les données pendant leur utilisation. Aucun niveau de sécurité maximal ne peut être revendiqué avant revue de conception, tests et audit indépendant.

## Ouvrir le projet

Ouvrir le dossier dans Android Studio, avec JDK 17 et Gradle 8.11.1 ou compatible avec Android Gradle Plugin 8.9.2, synchroniser Gradle, puis lancer la configuration app sur un appareil ou émulateur Android.

## Étapes prévues

1. Socle Android, interface et primitives locales.
2. Terminer l'appairage mutuel QR : comparaison des deux empreintes, échange effectif des défis/réponses entre appareils et raccordement de l’interface au répertoire chiffré des appareils approuvés.
3. Intégrer le coffre chiffré, puis transport P2P local et échanges de messages.
4. Transport Internet direct, avec indication claire des limites de connectivité.
5. Audio/vidéo direct et fichiers.
6. Tests de sécurité, revue cryptographique et audit indépendant.

## Sécurité du développement

Ne jamais ajouter de clé privée, secret, PIN, sauvegarde de clés ou donnée personnelle dans Git. Ne pas inventer de protocole cryptographique : privilégier des protocoles normalisés et des implémentations maintenues, après validation de leur licence et de leur compatibilité.
