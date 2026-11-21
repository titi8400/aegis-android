# AEGIS — Android

AEGIS est un projet de communication Android de pair à pair (P2P), destiné à la famille et aux proches.

## État du projet

**Version 0.3.0 — prototype en développement.** Le dépôt contient une application Android native Kotlin/Jetpack Compose, un écran de verrouillage PIN/biométrie et une première primitive d'identité avec Android Keystore. Ce n'est pas encore une messagerie opérationnelle ni un produit audité.

## Fonctions présentes dans le prototype

- Configuration d'un PIN indépendant de 6 à 12 chiffres.
- Vérification du PIN par PBKDF2-HMAC-SHA256 avec sel aléatoire.
- Authentification biométrique forte via AndroidX BiometricPrompt lorsque l'appareil la prend en charge.
- Verrouillage après 60 secondes sans interaction et lorsque l'application passe en arrière-plan.
- Temporisation progressive après les échecs de PIN.
- Après 10 échecs comptabilisés, suppression de la clé d'identité Android Keystore et réinitialisation du verrouillage local.
- Création manuelle d'une identité de signature ECDSA P-256 dans Android Keystore.

**Attention :** la suppression après 10 échecs concerne uniquement l'identité cryptographique de ce prototype. Elle ne constitue pas un effacement garanti de toutes les données du téléphone. Le compteur local est modifiable par un attaquant ayant le contrôle de l'appareil, pouvant effacer les données de l'application ou restaurer un état antérieur. Le coffre de fichiers chiffrés est disponible comme primitive technique, mais il n'est pas encore relié à une base de messages ni à l'interface.

## Décisions d'architecture

- Android natif : Kotlin, Jetpack Compose.
- Communication visée : P2P strict, sans serveur applicatif ni relais.
- Identité : paire de clés créée localement ; seule la clé publique sera partagée via QR code.
- Clé privée : Android Keystore, non exportable par cette API ; protection matérielle selon les capacités de l'appareil.
- Données : coffre local de fichiers AES-256-GCM, clé dédiée non exportable via Android Keystore, fichiers placés dans le répertoire interne exclu des sauvegardes Android.
- Récupération : deuxième appareil de confiance, avec approbation explicite des deux appareils.
- Interface : sombre, technique, accents cyan.

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
2. Identité cryptographique, QR d'appairage authentifié et intégration du coffre local chiffré.
3. Transport P2P local et échanges de messages.
4. Transport Internet direct, avec indication claire des limites de connectivité.
5. Audio/vidéo direct et fichiers.
6. Tests de sécurité, revue cryptographique et audit indépendant.

## Sécurité du développement

Ne jamais ajouter de clé privée, secret, PIN, sauvegarde de clés ou donnée personnelle dans Git. Ne pas inventer de protocole cryptographique : privilégier des protocoles normalisés et des implémentations maintenues, après validation de leur licence et de leur compatibilité.
