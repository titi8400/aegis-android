# AEGIS — Android

AEGIS est une application Android native de communication privée, conçue autour d'une architecture pair à pair. Le dépôt est un prototype technique : il ne doit pas être utilisé pour des communications sensibles avant des essais sur appareils réels et un audit indépendant.

## État actuel

**Version 0.10.0 — prototype P2P sur réseau local.**

| Brique | État |
|---|---|
| Verrouillage PIN et biométrie | Implémenté |
| Identité ECDSA P-256 dans Android Keystore | Implémentée |
| Appairage QR mutuel hors ligne | Implémenté |
| Registre local chiffré des appareils approuvés | Implémenté |
| Découverte des appareils approuvés sur le même LAN | Implémentée |
| Connexion TCP directe avec TLS mutuel et épinglage de clés | Implémentée dans le code |
| Échange de messages texte sur cette connexion | Interface et transport implémentés |
| Historique local par pair chiffré AES-256-GCM | Implémenté |
| Messages persistants chiffrés | À intégrer |
| Pièces jointes, photos, vidéos et notes vocales | À développer |
| Appels audio/vidéo | À développer |
| Messages éphémères | À développer |
| Partage de position | À développer |
| Récupération par deuxième appareil | À développer |
| Tests sur deux téléphones physiques et audit indépendant | À réaliser |

Le code de transport LAN est une première implémentation et n'a pas encore été validé sur deux appareils physiques. La réussite de la compilation et des tests unitaires ne prouve pas à elle seule le bon fonctionnement réseau ni la sécurité de bout en bout. L'historique local est conservé par appareil ; il n'est pas synchronisé entre les appareils.

## Architecture technique

- Android natif : Kotlin, Jetpack Compose, minSdk 26.
- Identité : clé ECDSA P-256 générée localement dans Android Keystore ; la clé privée n'est pas exportée par l'API de l'application.
- Appairage : invitations QR signées, défi-réponse signé, comparaison indépendante des empreintes SHA-256 et approbation manuelle.
- Répertoire de confiance : métadonnées chiffrées dans le coffre local AES-256-GCM.
- Réseau local : découverte UDP limitée au LAN, puis connexion TCP directe.
- Authentification réseau : TLS mutuel avec certificat d'identité temporaire signé par la clé Android Keystore et vérification de la clé publique par rapport au répertoire local des appareils approuvés.
- Trames applicatives : longueur préfixée, taille maximale de 1 Mio.
- Aucun serveur applicatif, service de rendez-vous ou relais n'est utilisé.

## Appairage QR hors ligne

1. Sur l'appareil A, initialise l'identité et crée une invitation QR.
2. Sur l'appareil B, scanne l'invitation.
3. B crée un défi signé et affiche le QR correspondant.
4. A scanne le défi et génère la réponse signée.
5. B scanne la réponse.
6. Les deux personnes comparent les empreintes SHA-256 complètes par un canal indépendant.
7. Chaque appareil enregistre explicitement l'autre dans son répertoire local.

L'invitation expire après cinq minutes ; le défi et la réponse après 90 secondes. Le QR ne contient aucune clé privée. Une confirmation cochée dans l'application ne remplace pas la comparaison indépendante réelle.

## Première connexion P2P locale

1. Les deux appareils doivent être appairés et avoir enregistré mutuellement leurs clés.
2. Ils doivent être connectés au même réseau Wi-Fi ou LAN ; les réseaux invités avec isolation des clients peuvent bloquer les connexions.
3. Ouvre « Messagerie P2P locale » sur les deux appareils.
4. L'écran recherche les appareils de confiance via des annonces UDP locales.
5. Sur l'un des appareils, active « Attendre un pair ».
6. Sur l'autre, sélectionne l'appareil détecté puis appuie sur « Connecter ».
7. Après validation du certificat et de la clé épinglée par TLS mutuel, les messages texte peuvent être échangés directement.

Le port TCP est 39841 et le port UDP de découverte est 39842. Ces ports ne sont utilisés que sur le réseau local. La découverte UDP est une indication de présence, jamais une preuve d'identité ; seule la négociation TLS mutuellement authentifiée autorise la session.

## Limites réseau importantes

Cette version ne fait pas de traversée NAT, de relais TURN, de serveur de rendez-vous ou de connexion Internet directe automatique. Elle fonctionne uniquement si les appareils peuvent se joindre directement sur leur réseau IP. Les opérateurs mobiles, les pare-feu, les NAT, l'isolation Wi-Fi et les réseaux distincts peuvent empêcher une connexion. Il n'existe pas de garantie de connexion entre deux réseaux éloignés sans mécanisme de rendez-vous ou de traversée NAT ; l'ajout d'un relais serait contraire au choix d'architecture retenu.

## Protections locales et limites

- PIN de 6 à 12 chiffres, vérifié par PBKDF2-HMAC-SHA256 avec sel aléatoire.
- Authentification biométrique forte via AndroidX BiometricPrompt si disponible.
- Verrouillage après 60 secondes d'inactivité et au passage en arrière-plan.
- Temporisation progressive des tentatives PIN.
- Au dixième échec enregistré, suppression de la clé d'identité et réinitialisation du verrouillage local.
- Coffre local AES-256-GCM utilisant une clé Android Keystore distincte.

Le compteur PIN est stocké dans les préférences privées de l'application et n'est pas inviolable. Un attaquant contrôlant le système peut manipuler les données, l'horloge ou l'état restauré. La suppression d'une clé ou d'un fichier ne garantit pas l'effacement physique de toutes les cellules flash. La sécurité dépend également de l'intégrité du système Android et des appareils des correspondants.

## Construction

- Android Studio
- JDK 17
- Android Gradle Plugin 8.9.2
- Gradle 8.11.1
- compileSdk 35, minSdk 26, targetSdk 35

La CI GitHub exécute les tests unitaires JVM puis construit l'APK Debug. L'APK Debug n'est pas une version de production signée pour distribution.

## Priorités de développement

1. Valider le transport TLS sur plusieurs versions et fabricants Android.
2. Ajouter une vraie couche de messages avec stockage local chiffré, gestion des accusés et des interruptions.
3. Ajouter les transferts de fichiers par blocs, reprise et limites de taille.
4. Concevoir appels audio/vidéo directs sans serveur ni relais, en documentant les limites NAT.
5. Concevoir la récupération par second appareil sans exporter de clé privée.
6. Faire réaliser une revue cryptographique et un audit indépendant avant utilisation réelle.

Ne jamais ajouter de clé privée, secret, PIN, donnée personnelle ou fichier de sauvegarde sensible dans Git.
