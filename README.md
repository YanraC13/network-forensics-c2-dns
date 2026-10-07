# Analyse forensique réseau : beaconing C2 et tunnel DNS

TP d'analyse forensique (Bachelor 3 Cybersécurité, Ynov Montpellier, juin 2026).
À partir d'un jeu de données fourni pour l'exercice (NetFlow, connexions en mémoire, arbre des processus, logs DNS et pare-feu), il fallait dire si la machine **10.0.5.23** était compromise.

**Conclusion :** la machine est très probablement compromise par un implant de type **C2**, avec une **exfiltration par tunnel DNS**.

---

## Méthode : 9 questions dans l'ordre

1. Quels flux sont inhabituels ?
2. Y a-t-il une périodicité ?
3. Y a-t-il des signes de beaconing ?
4. Quels processus portent les connexions ?
5. Le parent de chaque processus est-il légitime ?
6. Y a-t-il des signes de tunnel DNS ?
7. Les logs du pare-feu confirment-ils les flux ?
8. Quels artefacts soutiennent l'hypothèse ?
9. Quelle hypothèse, avec quel niveau de confiance ?

## Constats

**Flux suspects**

| Flux | Pourquoi c'est suspect |
|---|---|
| 10.0.5.23 → 185.221.87.44:**4444** | Port atypique, contacté **toutes les 30 s** avec un volume presque constant → beaconing |
| 10.0.5.23 → 8.8.8.8:53 | Requêtes DNS de **980 à 1 090 octets**, contre 82 pour une requête normale |
| 10.0.5.23 → 104.26.3.2:443 | 154 321 octets : téléchargement légitime ou dépôt d'outils (staging) ? À clarifier |

**Processus masqué**

```
services.exe (568)
└─ explorer.exe (812)
   └─ cmd.exe (2890)
      └─ svchost.exe (3248)   ← contacte 185.221.87.44:4444
```
Un vrai `svchost.exe` est toujours lancé par `services.exe`. Ici, il est lancé par `cmd.exe` : c'est un processus malveillant qui se fait passer pour un processus système (*masquerading*).

**Tunnel DNS : 4 indices qui vont dans le même sens**

1. Requêtes plus de 12 fois plus grosses que la normale.
2. Sous-domaines aléatoires (`ajd83jdk2k2k2.domain-example.com`…) : des données encodées.
3. Rafale de 5 requêtes en 5 secondes, chacune avec un sous-domaine différent.
4. Tailles croissantes (980 → 1 024 → 1 058 → 1 077 → 1 090) : un fichier envoyé en morceaux.

**Pare-feu :** les flux 4444 et DNS sont en `ALLOW OUTBOUND`, ce qui confirme les flux vus dans le NetFlow.

## Niveau de confiance

- **Élevé** sur la présence d'une activité malveillante : plusieurs indices cohérents.
- **Modéré** sur sa nature exacte. Pour confirmer, il faudrait analyser le binaire du PID 3248, vérifier la réputation de 185.221.87.44 (threat intel), décoder les labels DNS et clarifier le flux 443.

**Recommandation :** isoler la machine et poursuivre l'investigation.

## Ce que j'en retiens

- Un seul indice ne prouve rien. C'est la **convergence** de plusieurs sources (réseau, mémoire, DNS, pare-feu) qui fonde une conclusion.
- L'arbre des processus est un réflexe à avoir : un processus système lancé par le mauvais parent est un signal fort.
- Il faut annoncer son niveau de confiance et ce qui reste à vérifier.
