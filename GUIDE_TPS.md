# Guide des scripts — Lab Python Sécurité (ITIS)

Ce document explique, script par script, ce que fait chaque TP du dépôt, comment il fonctionne et quelles notions il illustre. Il complète le `README.md`, qui se limite à la liste des commandes.

Tous les scripts se lancent depuis la racine du dépôt, dans le terminal du Codespace, avec `python3 <nom_du_fichier>`. Plusieurs d'entre eux lisent ou génèrent des fichiers dans le répertoire courant, donc ne les lancez pas depuis un autre dossier.

## Sommaire

**Jour 1 — Reconnaissance, scanning et réseau**
`tp1_scanner.py`, `tp2_ping_sweep.py`, `tp3_arp_sniffer.py`, `tp4_ssh_bruteforce.py`

**Jour 2 — Analyse de logs, cryptographie et forensics**
`tp2_log_parser.py`, `tp3_crypto.py`, `tp7_hash_cracker.py`, `tp8_pe_analyzer.py`

**Jour 3 — Threat intelligence, audit web et CTF**
`tp9_threat_intel.py`, `tp10_web_audit.py`, `tp11_ctf_final.py`

## Environnement

Le conteneur de développement est construit à partir de `python:3.10-bullseye`. Il installe les outils système `nmap` et `netcat-openbsd`, ainsi que les bibliothèques Python `python-nmap`, `requests`, `cryptography`, `pefile`, `rich`, `python-dotenv` et `beautifulsoup4`.

La bibliothèque `rich` revient dans presque tous les scripts : elle sert à produire des tableaux et du texte coloré dans le terminal. Les balises que vous voyez dans le code, du type `[bold green]...[/bold green]`, sont sa syntaxe de mise en forme et n'ont rien à voir avec la logique de sécurité.

## Jour 1 — Reconnaissance, scanning et réseau

### tp1_scanner.py — Scan de ports TCP

Le script pilote le binaire `nmap` depuis Python via le wrapper `python-nmap` et scanne la cible publique `scanme.nmap.org`, que l'équipe Nmap met officiellement à disposition pour l'entraînement.

Le cœur du script tient dans l'appel `nm.scan(hosts=target, arguments='-sT -F')`. L'option `-sT` demande un scan *TCP Connect*, c'est-à-dire une poignée de main TCP complète : le script ouvre réellement la connexion puis la referme. C'est le mode le plus bruyant et le plus facilement journalisé par la cible, mais c'est le seul qui fonctionne sans privilèges root, ce qui est précisément le cas dans un conteneur. L'option `-F` restreint le scan aux cent ports les plus courants pour accélérer l'exécution.

Le reste du code parcourt la structure de résultats renvoyée par `python-nmap`, imbriquée en trois niveaux : les hôtes, puis les protocoles, puis les ports, chacun portant un état (`open`, `closed`, `filtered`) et un nom de service deviné à partir du numéro de port.

La notion à retenir est la différence entre un scan TCP Connect et un scan SYN (`-sS`), ce dernier n'achevant jamais la poignée de main et nécessitant la capability `NET_RAW`, absente du conteneur par défaut.

### tp2_ping_sweep.py — Découverte d'hôtes multithreadée

Malgré son nom, ce script ne fait pas de ping ICMP : il teste la joignabilité en tentant d'ouvrir une socket TCP sur les ports 80, 443 et 22 de chaque cible. C'est un contournement classique, car ICMP demande des privilèges bruts et se retrouve souvent bloqué par les pare-feux, alors qu'une connexion TCP sur un port de service courant passe presque partout.

La fonction `check_host` crée une socket, lui applique un délai d'attente d'une seconde et demie, puis utilise `connect_ex`. Cette variante de `connect` renvoie un code d'erreur au lieu de lever une exception, et un retour à zéro signifie que le port est ouvert. Dès qu'un des trois ports répond, l'hôte est considéré comme actif.

L'intérêt pédagogique principal est le `ThreadPoolExecutor` avec dix workers. Les cinq cibles sont testées en parallèle plutôt que l'une après l'autre : sans cela, une cible injoignable ferait attendre tout le reste pendant quatre secondes et demie. C'est exactement le mécanisme qu'utilisent les scanners réels pour balayer un `/24` en quelques secondes.

Notez que `192.168.1.254` figure dans la liste : depuis un Codespace, cette adresse privée n'est évidemment pas joignable et remontera systématiquement comme inactive. C'est volontaire, cela illustre la différence entre un scan depuis le cloud et un scan depuis le réseau local.

### tp3_arp_sniffer.py — Détection d'ARP poisoning

Ce script se déroule en deux temps. Il fabrique d'abord un fichier de capture `traffic_sample.pcap` contenant trois réponses ARP forgées avec Scapy, puis il relit ce fichier et cherche l'anomalie.

Le principe de détection est simple et c'est toute la valeur du TP : le script construit un dictionnaire associant chaque adresse IP à l'ensemble des adresses MAC vues pour elle. Dans un réseau sain, cette relation est de un pour un. Dès qu'une même IP apparaît avec deux MAC différentes, il y a conflit, et c'est la signature d'une attaque d'empoisonnement du cache ARP où un attaquant se fait passer pour la passerelle.

Le jeu de données contient précisément ce cas : l'IP `192.168.1.1` est d'abord annoncée par `00:11:22:33:44:55`, puis revendiquée par `DE:AD:BE:EF:00:01`. Le filtre `pkt[scapy.ARP].op == 2` ne retient que les réponses ARP (*is-at*), qui sont les paquets qu'un attaquant émet en masse pour polluer les caches.

Attention, ce script importe `scapy`, qui n'est pas installée par le Dockerfile. Il faudra l'ajouter pour qu'il s'exécute.

### tp4_ssh_bruteforce.py — Attaque par dictionnaire sur SSH

Le script parcourt une liste de mots de passe et tente une connexion SSH pour chacun, en s'arrêtant au premier succès, avec une temporisation de trois dixièmes de seconde entre deux essais.

Le point important à comprendre est la gestion différenciée des exceptions Paramiko, car chacune raconte une histoire différente pour l'attaquant. Une `AuthenticationException` signifie que le serveur est joignable, que le service SSH répond, et que seul le mot de passe est faux : c'est un échec encourageant. Une `SSHException` signale un problème de protocole ou, plus souvent, un mécanisme anti-brute-force qui a coupé la connexion. Une exception générique indique en général que rien n'écoute sur le port.

Il faut savoir que ce TP est truqué : une condition en dur au début de la fonction renvoie un succès dès que le mot de passe vaut `secret123`, sans jamais contacter de serveur. C'est un choix assumé pour que la démonstration fonctionne dans un conteneur sans serveur SSH, mais cela veut dire que le code Paramiko en dessous n'est jamais réellement exercé. Ce script importe par ailleurs `paramiko`, absente elle aussi du Dockerfile.

## Jour 2 — Analyse de logs, cryptographie et forensics

### tp2_log_parser.py — Détection d'attaques dans un journal HTTP

Ce script lit `access.log` ligne par ligne et cherche deux familles d'attaques, avec deux techniques distinctes.

La première est la détection de force brute, fondée sur le comptage. Chaque ligne portant un code HTTP 401 incrémente un compteur associé à l'adresse IP source, et toute IP cumulant au moins trois échecs déclenche une alerte. C'est un raisonnement par seuil, celui-là même qu'appliquent fail2ban ou une règle de corrélation SIEM.

La seconde est la détection d'injection SQL par expression régulière, qui cherche des mots-clés comme `union`, `select` ou `drop`, ainsi que l'apostrophe et la chaîne `1=1`. C'est l'occasion de discuter des limites de l'approche par signature : le motif n'utilise aucune délimitation de mot, si bien que le simple `or` déclenchera une alerte sur n'importe quelle URL contenant ces deux lettres. Les faux positifs sont donc massifs, et c'est un excellent point de départ pour parler du compromis entre taux de détection et bruit dans un SOC.

Le `Counter` de la bibliothèque standard, utilisé ici, est un dictionnaire spécialisé dans le comptage qui évite d'avoir à initialiser chaque clé.

### tp3_crypto.py — Chiffrement symétrique AES-256-CBC

Le script chiffre puis déchiffre une phrase avec AES-256 en mode CBC, en s'appuyant sur la bibliothèque `cryptography`.

Trois éléments méritent l'attention. D'abord le vecteur d'initialisation, seize octets tirés aléatoirement par `os.urandom` à chaque chiffrement : c'est lui qui garantit que chiffrer deux fois le même message produit deux résultats différents. Il n'est pas secret, ce qui explique qu'il soit simplement concaténé devant le texte chiffré avant d'être ré-extrait au déchiffrement.

Ensuite le remplissage PKCS7, nécessaire parce qu'AES travaille sur des blocs de cent vingt-huit bits et qu'un message de longueur quelconque doit être complété pour atteindre un multiple de cette taille.

Enfin la clé, trente-deux octets soit deux cent cinquante-six bits, générée ici aléatoirement à chaque exécution. En conditions réelles, elle proviendrait d'une fonction de dérivation à partir d'un mot de passe, et sa gestion serait le vrai problème.

Une remarque utile pour la suite du cours : le mode CBC assure la confidentialité mais pas l'intégrité, un attaquant pouvant modifier le texte chiffré sans être détecté. C'est pourquoi on lui préfère aujourd'hui un mode authentifié comme GCM.

### tp7_hash_cracker.py — Cassage d'empreintes par dictionnaire

Le script calcule l'empreinte MD5 de chaque mot d'une liste et la compare à une empreinte cible, en mesurant le temps et le nombre de tentatives.

Il illustre la propriété fondamentale des fonctions de hachage : elles sont à sens unique, on ne peut pas inverser une empreinte. La seule attaque possible consiste donc à deviner le mot d'origine, à le hacher et à comparer. Toute la difficulté se déplace vers la qualité du dictionnaire et la vitesse de calcul.

C'est aussi pour cela que MD5 est un mauvais choix pour stocker des mots de passe, non pas tant parce qu'il est cassé sur le plan des collisions, mais parce qu'il est extrêmement rapide à calculer, ce qui profite à l'attaquant. Les fonctions dédiées comme bcrypt ou Argon2 sont volontairement lentes et paramétrables.

Le titre du TP dans le `README.md` mentionne MD5 et SHA-256, mais le script n'implémente que MD5. L'ajout de SHA-256 constitue un bon exercice de prolongement, tout comme l'ajout d'un sel pour montrer qu'il rend inutilisables les tables précalculées.

### tp8_pe_analyzer.py — Analyse statique d'un binaire Windows

Le script génère un faux exécutable PE minimal, puis l'analyse comme le ferait un outil de forensics.

Il commence par calculer les empreintes MD5 et SHA-256 du fichier complet. Ce sont les identifiants qu'on soumet à VirusTotal ou qu'on compare à une base d'indicateurs de compromission pour savoir si l'échantillon est déjà connu.

Il ouvre ensuite le fichier avec `pefile` et énumère ses sections. Un exécutable Windows est découpé en zones nommées, typiquement `.text` pour le code, `.data` pour les données initialisées et `.rsrc` pour les ressources. Le script affiche pour chacune son nom, son adresse virtuelle et sa taille sur disque.

C'est justement cette comparaison qui est intéressante en analyse de malware : un écart important entre la taille sur disque et la taille en mémoire trahit souvent un binaire empaqueté, qui se décompresse à l'exécution pour échapper à l'analyse statique. Des noms de sections inhabituels comme `UPX0` sont un autre indice classique.

L'analyse est dite statique parce que le fichier n'est jamais exécuté, ce qui la rend sans risque.

## Jour 3 — Threat intelligence, audit web et CTF

### tp9_threat_intel.py — Enrichissement d'adresses IP

Le script interroge l'API publique `ip-api.com` pour trois adresses et récupère le pays, l'organisation propriétaire et un indicateur d'hébergement.

Il illustre la notion d'enrichissement, centrale dans le travail d'un analyste SOC : une adresse IP seule ne dit rien, c'est le contexte qui lui donne du sens. Le champ `hosting`, en particulier, distingue une adresse résidentielle d'une adresse de centre de données. Une connexion d'utilisateur qui provient d'un datacenter est suspecte, parce qu'elle signale souvent un VPN, un proxy ou un nœud de sortie Tor, ce qu'illustre la troisième adresse de la liste.

Le script utilise correctement un délai d'attente de trois secondes sur la requête, ce qui évite qu'une API lente ne bloque toute l'exécution. En revanche, l'appel se fait en HTTP simple et non en HTTPS : la réponse circule donc en clair, ce qui est un mauvais réflexe à corriger sur un outil de sécurité.

### tp10_web_audit.py — Audit des en-têtes de sécurité HTTP

Le script récupère une page web et vérifie la présence de quatre en-têtes de sécurité, puis compte les formulaires HTML.

Chacun de ces en-têtes répond à une menace précise. `Strict-Transport-Security` force le navigateur à n'utiliser que HTTPS et contre les attaques de rétrogradation. `X-Frame-Options` empêche l'inclusion de la page dans une iframe et bloque le détournement de clic. `X-Content-Type-Options` interdit au navigateur de deviner le type d'un contenu, ce qui évite qu'un fichier téléversé ne soit interprété comme du script. `Content-Security-Policy`, le plus puissant et le plus complexe, restreint les sources depuis lesquelles scripts et styles peuvent être chargés, et constitue la défense de fond contre le XSS.

La seconde partie utilise BeautifulSoup pour analyser le HTML et compter les balises `form`. C'est la première étape d'une cartographie de surface d'attaque : chaque formulaire est un point d'entrée où l'on ira ensuite chercher des injections ou l'absence de jeton anti-CSRF.

Le script dépend d'un service externe, `httpbin.org`. Si la cible est indisponible, il affichera une erreur de connexion sans que rien ne soit cassé de votre côté.

### tp11_ctf_final.py — Challenge de synthèse

Le script enchaîne les deux techniques vues dans la semaine. La première étape casse une empreinte MD5 par dictionnaire, reprenant le principe du TP7, avec `12345` comme solution. La seconde déchiffre un message avec Fernet, la couche de haut niveau de la bibliothèque `cryptography`, qui combine AES-128 en mode CBC et une signature HMAC-SHA256 pour assurer à la fois la confidentialité et l'intégrité.

Il faut être lucide sur la portée de l'exercice : la clé Fernet est générée par le script lui-même juste avant d'être utilisée pour déchiffrer. Il n'y a donc aucun challenge réel dans la seconde étape, seulement une démonstration du cycle chiffrement puis déchiffrement. Un vrai CTF exigerait que la clé soit dérivée de la solution de l'étape précédente, ce qui constitue d'ailleurs le meilleur prolongement possible pour ce TP.

## Points d'attention

Quelques incohérences existent entre le `README.md` et les fichiers réellement présents, et il vaut mieux les connaître avant de chercher un script inexistant.

Le `README.md` annonce `tp5_log_parser.py` et `tp6_crypto_aes.py`, alors que les fichiers présents s'appellent `tp2_log_parser.py` et `tp3_crypto.py`. Les numéros 5 et 6 n'existent pas dans le dépôt, et deux numéros se retrouvent utilisés deux fois.

Deux scripts importent des bibliothèques qui ne sont pas installées par le Dockerfile, ce qui provoquera une erreur `ModuleNotFoundError` à l'exécution. Il s'agit de `scapy` pour `tp3_arp_sniffer.py` et de `paramiko` pour `tp4_ssh_bruteforce.py`. Pour les ajouter durablement, complétez la liste `pip install` du fichier `.devcontainer/Dockerfile` puis reconstruisez le conteneur. Pour un dépannage immédiat, un `pip install scapy paramiko` dans le terminal suffit, mais l'installation sera perdue à la prochaine reconstruction.

Enfin, tous ces scripts ne visent que des cibles publiques d'entraînement, des adresses locales ou des données générées sur place. Les techniques qu'ils illustrent, scan de ports, attaque par dictionnaire et cassage d'empreintes, ne doivent être employées que sur des systèmes dont vous avez l'autorisation écrite de tester la sécurité.
