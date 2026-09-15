# Captures d'écran à fournir

Le rapport (`main.tex`) référence cinq captures d'écran réelles. Tant qu'elles
ne sont pas ajoutées ici, le document affiche un cadre avec le texte de la
légende à la place de l'image — c'est voulu : mieux vaut un espace réservé
visible qu'une fausse capture générée.

| Fichier attendu | Figure | Chapitre | Contenu à capturer | Commande à lancer avant la capture |
|---|---|---|---|---|
| `ii1-semgrep-run.png` | II.x | II | Une exécution réelle de `semgrep scan` dans le terminal (ou son JSON ouvert dans un éditeur), montrant les fichiers analysés et le nombre de résultats trouvés — sert à ancrer l'explication du SAST dans quelque chose de concret | `semgrep scan --config p/php sample_vuln_app/public/login.php` (ou la commande complète du chapitre IV) |
| `iv1-menu.png` | IV.1 | IV | Le menu interactif au lancement, montrant les 5 analyses + "Run everything at once" + "Quit" | `python main.py sample_vuln_app` |
| `iv2-routage.png` | IV.2 | IV | La sortie terminal d'une exécution `--all`, avec les lignes `... -> N file(s) selected` pour chaque analyse | `python main.py sample_vuln_app --all --report reports` |
| `iv3-rapport-vue-ensemble.png` | IV.3 | IV | Le haut de `report.html` dans un navigateur : tableau de routage, graphique par sévérité, bandeau "à corriger en premier" si une CVE KEV est présente | ouvrir `reports/report.html` après le scan ci-dessus |
| `iv4-fiche-vulnerabilite.png` | IV.4 | IV | Une fiche de vulnérabilité détaillée dans `report.html` — idéalement l'injection SQL de `public/login.php` (CWE-89) | faire défiler jusqu'à cette fiche dans `report.html` |

## Comment les ajouter

1. Prendre les 5 captures (PNG, largeur raisonnable — 1400 px suffit).
2. Les placer dans ce dossier sous exactement ces noms.
3. Dans `main.tex`, pour chaque figure, remplacer le bloc
   `\fbox{\parbox{...}{...}}` par la ligne `\includegraphics` déjà présente
   juste en dessous, en commentaire (`%`) — il suffit de décommenter cette
   ligne et de supprimer le bloc `\fbox{...}` au-dessus.

Aucune capture ne doit être générée artificiellement : le rapport doit
montrer le programme tel qu'il se comporte réellement. Les autres schémas du
rapport (pipeline, routage, exclusions, principe du SAST) sont des diagrammes
TikZ dessinés directement dans `main.tex` — fidèles au code, pas des captures.
