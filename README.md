# AEGIS — Android

AEGIS est un prototype Android natif de communication privée pair à pair. Il est conçu pour fonctionner sans serveur applicatif ni relais. Il ne doit pas être utilisé pour des communications sensibles avant des essais sur appareils physiques et un audit indépendant.

## État du projet

**Version 0.16.0 — prototype P2P sur réseau local ; socle de récupération en cours.**

| Fonction | État |
|---|---|
| Verrouillage PIN et biométrie | Implémenté |
| Identité ECDSA P-256 dans Android Keystore | Implémentée |
| Appairage QR mutuel hors ligne | Implémenté |
| Répertoire local chiffré des appareils approuvés | Implémenté |
| Sélection d'un correspondant approuvé, même hors ligne | Implémentée |
| Découverte des appareils approuvés sur le même LAN | Implémentée |
| Connexion TCP directe avec TLS mutuel et épinglage des clés | Implémentée dans le code |
| Messages texte et historique local chiffré | Implémentés |
| File d'attente hors ligne chiffrée | Implémentée, 200 messages maximum par correspondant |
| Accusé de livraison applicatif | Le destinataire confirme l'enregistrement local avant retrait de la file d'attente |
| Messages texte éphémères | Implémentés : 1 min, 1 h et 24 h |
| Transfert de fichiers | Implémenté jusqu'à 20 Mio, blocs de 512 Kio, vérification SHA-256 |
| Stockage local des fichiers reçus | Chiffré AES-256-GCM |
| Notes vocales | WAV, 30 secondes maximum, transfert comme fichier |
| Partage de position ponctuel | Implémenté avec autorisation et action explicites |
| Appels audio/vidéo | Première intégration WebRTC, signalisation TLS, ICE hôte uniquement |
| Reprise de transfert de fichiers interrompu | À développer |
| Sérialisation versionnée des archives de récupération | Implémentée avec liste blanche de données utilisateur et limites de taille |
| Chiffrement des archives de récupération | AES-256-GCM avec secret aléatoire distinct ; tests unitaires ajoutés |
| Export/restauration depuis l'interface | À intégrer |
| Transfert P2P de l'archive entre les deux appareils | À intégrer |
| Réappairage des contacts après restauration | À intégrer |
| Tests sur deux téléphones physiques | À réaliser |
| Audit cryptographique indépendant | À réaliser |

La compilation et les tests automatisés ne prouvent pas le bon fonctionnement réseau ni la sécurité globale. Les appels, la caméra, le microphone et le transfert de données doivent encore être testés sur deux appareils physiques.

## Architecture

- Kotlin natif, Jetpack Compose, minSdk 26.
- Clé d'identité ECDSA P-256 créée dans Android Keystore ; la clé privée n'est pas exportée par l'application.
- Invitations QR signées, défi-réponse signé, anti-rejeu et comparaison indépendante des empreintes.
- Répertoire des appareils approuvés et données locales chiffrés avec AES-256-GCM.
- Découverte UDP locale puis connexion TCP directe.
- TLS mutuel avec épinglage exact des clés publiques approuvées.
- Messages et accusés applicatifs transportés dans la session TLS authentifiée.
- Aucun serveur applicatif, serveur de rendez-vous, STUN, TURN ou relais.

## Messages et livraison hors ligne

Les messages sortants sont enregistrés dans une file d'attente locale chiffrée. Un correspondant approuvé peut être sélectionné même s'il n'est pas connecté. À la reconnexion, AEGIS transmet les messages en attente.

Le destinataire enregistre le message dans son historique chiffré avant d'envoyer un accusé applicatif contenant l'identifiant du message. L'expéditeur retire le message de sa file d'attente uniquement après réception de cet accusé. En cas de délai dépassé ou de rupture de connexion, le message reste en attente. Les identifiants permettent au stockage du destinataire de dédupliquer une retransmission.

Cet accusé signifie que le message a été enregistré dans l'historique local du destinataire ; il ne signifie pas qu'il a été lu. La livraison dépend du retour en ligne des deux appareils, de l'ouverture de l'application et de la joignabilité réseau. Il n'y a pas de service d'arrière-plan ni de livraison lorsque les appareils ne peuvent pas établir une connexion directe.

## Appairage QR

1. Sur l'appareil A, crée une invitation QR.
2. Sur l'appareil B, scanne l'invitation et crée un défi signé.
3. A scanne le défi et génère une réponse signée.
4. B scanne la réponse.
5. Les utilisateurs comparent les empreintes SHA-256 complètes par un canal indépendant.
6. Chaque appareil enregistre explicitement l'autre.

L'invitation expire après cinq minutes ; le défi et la réponse après 90 secondes. Le QR ne contient aucune clé privée. Une confirmation dans l'application ne remplace pas la comparaison indépendante.

## Connexion P2P locale

1. Les appareils doivent être appairés mutuellement.
2. Ils doivent pouvoir communiquer sur le même réseau local ; l'isolation des clients Wi-Fi peut bloquer la liaison.
3. Ouvre la messagerie P2P sur les deux appareils.
4. Active « Attendre un pair » sur l'un d'eux.
5. Sur l'autre, sélectionne l'appareil détecté puis connecte-toi.
6. Après authentification TLS mutuelle, les messages et fichiers peuvent être échangés.

Port TCP : 39841. Port UDP de découverte : 39842. La découverte UDP indique seulement une présence potentielle ; elle ne prouve pas l'identité. Seule la validation TLS mutuelle autorise la session.

## Limites réseau

Les appels WebRTC utilisent uniquement les candidats ICE hôtes, sans STUN ni TURN. La communication nécessite une connectivité IP directe, généralement sur le même réseau local. Il n'y a pas de traversée NAT, de relais ni de rendez-vous distant. Les pare-feu, réseaux mobiles, réseaux distincts ou l'isolation Wi-Fi peuvent empêcher la connexion.

## Sécurité locale et limites

- PIN de 6 à 12 chiffres, PBKDF2-HMAC-SHA256 avec sel aléatoire.
- Biométrie forte via AndroidX BiometricPrompt si l'appareil la prend en charge.
- Verrouillage après 60 secondes d'inactivité et au passage en arrière-plan.
- Temporisation progressive des tentatives PIN.
- Au dixième échec enregistré, suppression de la clé d'identité locale.
- Coffre AES-256-GCM avec clé Android Keystore distincte.
- Les messages éphémères sont purgés localement ; cela ne supprime pas les copies déjà consultées, exportées ou capturées par le destinataire.

Le compteur PIN n'est pas inviolable. La suppression d'une clé ou d'un fichier ne garantit pas l'effacement physique de toutes les cellules flash. Les données en clair peuvent exister temporairement en mémoire vive. La sécurité dépend aussi de l'intégrité d'Android et des appareils des correspondants.

## Construction

- Android Studio, JDK 17
- Android Gradle Plugin 8.9.2, Gradle 8.11.1
- compileSdk 35, minSdk 26, targetSdk 35

La CI exécute les tests unitaires JVM puis construit l'APK Debug. L'APK Debug n'est pas une version de production signée pour distribution.

## Étapes restantes

1. Tester l'appairage, la messagerie, les accusés, les transferts, les notes vocales et les appels sur deux téléphones physiques.
2. Implémenter la reprise des transferts de fichiers interrompus.
3. Concevoir et implémenter la récupération via un deuxième appareil de confiance sans exporter de clé privée.
4. Tester les scénarios de perte, reconnexion, restauration et révocation.
5. Faire réaliser une revue cryptographique et un audit indépendant avant toute utilisation réelle.

Ne jamais ajouter de clé privée, secret, PIN, donnée personnelle ou sauvegarde sensible dans Git.


## Récupération — socle technique 0.16.0

Le socle actuel sérialise uniquement les enregistrements de conversations et les fichiers reçus, puis chiffre l'archive avec AES-256-GCM. Le secret de récupération est aléatoire, distinct de la clé du coffre local et doit être transmis séparément à l'utilisateur. Les archives sont versionnées, bornées à 20 Mio et rejettent les identifiants non autorisés, les doublons et les données ajoutées en fin de fichier.

Les clés privées Android Keystore, l'identité de l'appareil, les codes PIN et le répertoire des appareils approuvés sont exclus de l'archive. Après restauration, l'appareil utilise sa propre identité et les contacts doivent être appairés de nouveau. À ce stade, l'interface de sauvegarde/restauration et le transfert P2P de l'archive ne sont pas encore disponibles.
