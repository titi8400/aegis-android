# Politique de sécurité AEGIS

## État du produit

AEGIS 0.15.0 est un prototype Android. Il comprend un appairage QR hors ligne, une liaison TCP sur réseau local avec TLS mutuel et épinglage des clés publiques, un historique local chiffré et une file d'attente de messages hors ligne. Le prototype n'a pas été audité et n'a pas encore été validé sur deux téléphones physiques. Ne pas l'utiliser pour des communications sensibles.

## Fonctions présentes dans le code

- PIN indépendant de 6 à 12 chiffres, vérifié par PBKDF2-HMAC-SHA256 avec sel.
- Biométrie via AndroidX BiometricPrompt lorsque l'authentificateur biométrique fort est disponible.
- Verrouillage après 60 secondes d'inactivité et au passage en arrière-plan.
- Temporisation progressive des échecs PIN.
- Au dixième échec enregistré, suppression de la clé d'identité locale.
- Identité ECDSA P-256 conservée dans Android Keystore.
- Invitations QR signées, défi-réponse signé, expiration et protection anti-rejeu.
- Répertoire des appareils de confiance stocké dans le coffre AES-256-GCM.
- Certificat TLS temporaire signé avec la clé Android Keystore, authentification mutuelle et épinglage des clés publiques approuvées.
- Trames du transport limitées à 1 Mio.
- Historique des conversations chiffré AES-256-GCM.
- File d'attente hors ligne chiffrée : 200 messages maximum par correspondant.
- Le destinataire enregistre le message dans son historique chiffré avant d'émettre un accusé applicatif sur la session TLS. L'expéditeur ne retire l'entrée de sa file qu'après réception de cet accusé.
- La livraison est au moins une fois au niveau du transport : si l'accusé est perdu après l'enregistrement distant, une retransmission peut survenir. Les identifiants de message servent à dédupliquer le stockage local.
- L'accusé confirme l'enregistrement local, pas la lecture.
- Les messages éphémères portent une expiration locale (1 minute, 1 heure ou 24 heures). La purge dépend de l'exécution de l'application et ne supprime pas les copies déjà exportées, capturées ou consultées.
- Fichiers reçus limités à 20 Mio, assemblés en mémoire, vérifiés par SHA-256 puis chiffrés dans le coffre local. Les transferts interrompus ne sont pas repris.
- Notes vocales enregistrées après autorisation du microphone, limitées à 30 secondes et transmises comme fichiers WAV.
- Partage de position ponctuel après action explicite et autorisation.
- Appels audio/vidéo utilisant une signalisation dans la session TLS et WebRTC/DTLS-SRTP. Aucun STUN/TURN ; seuls les candidats ICE hôtes sont utilisés.

## Limites connues

- La messagerie hors ligne est une file locale, pas un service de livraison en arrière-plan. Les deux appareils doivent pouvoir établir une connexion directe et l'application doit être active pour recevoir.
- Les appels et la liaison P2P n'ont pas encore été validés sur deux appareils physiques.
- La découverte UDP ne prouve jamais l'identité ; l'authentification TLS par clé épinglée est obligatoire.
- Pas de serveur de rendez-vous, traversée NAT ou relais ; les pairs doivent être directement joignables.
- Pas de reprise des transferts de fichiers interrompus.
- Pas de récupération des données via un deuxième appareil à ce stade.
- Le compteur PIN est stocké dans les préférences privées et n'est pas résistant à un appareil compromis, à l'effacement des données, à une restauration ou à une manipulation de l'horloge.
- La suppression d'une clé ne garantit pas l'effacement physique de toutes les cellules de mémoire flash.
- Les données en clair peuvent exister temporairement en mémoire vive ou être exposées sur un appareil compromis.
- Aucune revue cryptographique ni audit indépendant n'a été effectué.

## Principes obligatoires

- Aucun secret, clé privée, PIN ou donnée personnelle dans Git.
- Aucun algorithme cryptographique maison pour les communications.
- Toute modification du protocole, des certificats ou du stockage doit être accompagnée de tests et d'une revue.
- Les identités doivent être comparées par un canal indépendant lors de l'appairage initial.
- Les certificats réseau ne sont acceptés que si leur clé publique correspond à un appareil approuvé localement.
- Les erreurs d'authentification doivent fermer la connexion ; aucun mode non chiffré n'est autorisé.
- Les limites de connectivité P2P doivent être expliquées clairement.
- Un audit indépendant est nécessaire avant toute utilisation réelle.

## Signalement

Ne publiez pas de vulnérabilité exploitable dans une issue publique. Contactez le propriétaire du dépôt par un canal privé avant toute divulgation.
