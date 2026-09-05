# PortPeek

Un scanner de ports TCP simple et multithreadé, écrit en Python. PortPeek
teste une plage (ou une liste) de ports sur une cible et indique lesquels
sont ouverts, avec une tentative d'identification du service via une bannière
ou une liste de ports courants.

> ⚠️ **Avertissement légal** : n'utilise PortPeek que sur des systèmes que tu
> possèdes ou pour lesquels tu as une autorisation écrite explicite. Scanner
> des systèmes sans permission peut être illégal selon la juridiction. L'outil
> demande explicitement le flag `--i-have-authorization` avant de lancer un
> scan, comme rappel.

## Pourquoi ce projet

Étudiant en cybersécurité, je construis des petits outils pratiques pour
mon portfolio, en parallèle de ma pratique sur TryHackMe, OWASP Juice Shop
et des CTF. Le scan de ports est une des bases de la reconnaissance réseau
en pentest — ce projet me sert à en comprendre le fonctionnement de A à Z
plutôt que de me contenter d'utiliser Nmap sans savoir ce qu'il fait.

## Fonctionnement

1. Le nom d'hôte ou l'IP cible est résolu en adresse IP.
2. La liste des ports à tester est construite (plage ou liste explicite).
3. Un pool de threads tente une connexion TCP sur chaque port en parallèle
   (`socket.connect_ex`), ce qui évite d'attendre chaque port un par un.
4. Pour chaque port qui répond, PortPeek tente de récupérer une bannière
   (certains services s'annoncent juste après la connexion, comme SSH ou
   FTP) ; sinon il affiche le nom de service usuel associé à ce port.
5. Le résultat est affiché trié par numéro de port.

## Installation

```bash
git clone https://github.com/<toi>/portpeek.git
cd portpeek
```

Aucune dépendance externe : uniquement des modules intégrés à Python
(`socket`, `argparse`, `concurrent.futures`). Python 3.9+ requis.

## Utilisation

```bash
python portscanner.py --target 127.0.0.1 --ports 1-1024 --i-have-authorization
```

### Options

| Option | Description |
|---|---|
| `--target` | IP ou nom d'hôte de la cible (obligatoire) |
| `--ports` | Ports à scanner : plage (`1-1024`) ou liste (`22,80,443`). Défaut : `1-1024` |
| `--timeout` | Timeout de connexion en secondes (défaut : `0.5`) |
| `--threads` | Nombre de threads simultanés (défaut : `100`) |
| `--i-have-authorization` | Confirmation obligatoire que tu es autorisé à scanner la cible |

### Exemple

```bash
python portscanner.py --target 127.0.0.1 --ports 1-9000 --i-have-authorization
```

```
PortPeek — scanning 127.0.0.1 (127.0.0.1)
Ports: 9000 | Threads: 100 | Timeout: 0.5s
Started at 2026-09-05 19:25:53

PORT    STATE   SERVICE / BANNER
22      open    SSH
80      open    HTTP
8765    open    unknown

Scan completed in 1.24 seconds. 3 open port(s) found.
```

## Structure du projet

```
portpeek/
└── portscanner.py   # tout le scanner : parsing d'arguments, scan, affichage
```

Volontairement en un seul fichier pour ce projet — c'est assez petit pour
rester lisible, contrairement à un projet plus gros où découper en modules
devient utile.

## Limites connues

- Scan TCP « connect » classique uniquement (pas de scan SYN furtif comme
  Nmap, qui nécessite des privilèges root et l'accès aux sockets brutes).
- La récupération de bannière est basique : certains services ne renvoient
  rien tant qu'on ne leur envoie pas une requête adaptée (ex. HTTP a
  besoin d'un `GET` pour répondre).
- Pas de détection de version précise (contrairement à `nmap -sV`).

## Pistes d'amélioration

- [ ] Scan UDP en plus du TCP
- [ ] Détection de version plus fine (envoyer une requête adaptée par service)
- [ ] Export des résultats en JSON/CSV
- [ ] Barre de progression pendant le scan

## Licence

MIT.
