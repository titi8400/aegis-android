# AEGIS — Android

AEGIS est un projet privé de communication Android de pair à pair (P2P), conçu pour la famille et les proches.

## État du projet

**Socle initial v0.1 — en développement.** Ce dépôt contient le squelette Android natif Kotlin/Jetpack Compose et une première base de gestion de clés Android Keystore. Il ne constitue pas encore une application de messagerie opérationnelle ni un produit audité.

## Décisions d'architecture

- Android natif : Kotlin, Jetpack Compose.
- Communication visée : P2P strict, sans serveur applicatif ni relais.
- Identité : paire de clés générée localement ; seule la clé publique pourra être partagée via QR code.
- Clés privées : Android Keystore, non exportables lorsque le matériel et la version Android le permettent.
- Données : stockage local chiffré à concevoir avant toute persistance de contenu.
- Verrouillage : biométrie Android et code PIN indépendant.
- Récupération : second appareil de confiance, avec approbation explicite des deux appareils.
- Interface : sombre, technique, accents cyan.

## Limites à ne pas masquer

Le P2P strict ne garantit pas qu'une connexion Internet directe soit possible entre deux téléphones. NAT, pare-feu, opérateurs et réseaux Wi-Fi peuvent empêcher la connexion. Sans serveur de découverte ni relais, certains pairs ne pourront pas se joindre à distance. Les échanges de proximité restent une voie distincte à implémenter.

La suppression de clés ne garantit pas l'effacement physique de chaque bloc de mémoire flash. Un appareil compromis peut exposer les données pendant leur utilisation. Aucun niveau de sécurité maximal ne peut être revendiqué avant revue de conception, tests et audit indépendant.

## Ouvrir le projet

Ouvrir le dossier dans Android Studio (version compatible avec Android Gradle Plugin 8.9.2), synchroniser Gradle, puis lancer la configuration `app` sur un appareil ou émulateur Android.

## Étapes prévues

1. Socle Android, interface et gestion de clés locale.
2. Identité cryptographique, QR d'appairage et stockage chiffré.
3. Transport P2P local et échanges de messages.
4. Transport Internet direct, avec indication claire des limites de connectivité.
5. Audio/vidéo direct et fichiers.
6. Tests de sécurité, revue cryptographique et audit indépendant.

## Sécurité du développement

Ne jamais ajouter de clé privée, secret, code PIN, sauvegarde de clés ou donnée personnelle au dépôt Git. Ne pas inventer de protocole cryptographique : privilégier des protocoles normalisés et des implémentations maintenues, après validation de leur licence et de leur compatibilité.
