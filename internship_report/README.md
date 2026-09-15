# Rapport de stage (ENSIASD)

Rapport de stage d'initiation, en français, pour le projet CLI d'analyse
de sécurité statique.

## À compléter avant impression

Ouvrir `main.tex` et remplacer chaque `[À RENSEIGNER]` en haut du fichier :

```
\AuthorName        nom de l'étudiant
\StudentID         CNE / numéro d'étudiant
\AcademicYear      année universitaire, ex. 2025-2026
\SupervisorName    encadrant pédagogique
\HostOrg           organisme d'accueil
\HostSupervisor    maître de stage / service d'accueil
\InternshipPeriod  dates du stage
```

Ces informations ne pouvaient pas être devinées ou inventées ; elles doivent
être renseignées par l'étudiant. Trois sections de contenu personnel sont
aussi marquées `[À RENSEIGNER]` dans le corps du texte : Dédicaces,
Remerciements (paragraphe nominatif), et la présentation de l'organisme
d'accueil (chapitre I, sections I.1 et I.2).

Voir aussi `figures/README.md` : cinq captures d'écran réelles sont
attendues (une au chapitre II, quatre au chapitre IV) et n'ont pas encore
été prises.

## Compilation

Le document est écrit pour **XeLaTeX** (police Times New Roman réelle sous
Windows). Compiler **deux fois** pour que la table des matières et les
renvois se stabilisent :

```bat
cd internship_report
xelatex -interaction=nonstopmode main.tex
xelatex -interaction=nonstopmode main.tex
```

pdfLaTeX fonctionne aussi (utilise `mathptmx`, un clone de Times, au lieu du
fichier de police Times New Roman).

**Non vérifié dans cette session** : aucun outil `xelatex`/`pdflatex` n'était
installé sur la machine utilisée pour générer ce fichier — le document n'a
donc pas pu être compilé pour confirmer l'absence d'erreur. La syntaxe a été
relue manuellement (accolades équilibrées, échappements des `_` dans les
`\texttt{}`, blocs de code en environnements `lstlisting` sûrs), mais une
première compilation reste à faire avant impression. Si une erreur apparaît,
elle se situera très probablement dans un des diagrammes TikZ ou dans le
diagramme de Gantt (`pgfgantt`), les parties les plus denses en syntaxe.
Ces diagrammes ont été relus caractère par caractère lors de la révision
de 2026 (voir section « Contenu de la révision » ci-dessous) et un
balayage automatisé a confirmé l'absence des deux erreurs de syntaxe
TikZ les plus fréquentes (commande perdue après un retour à la ligne,
mode mathématique mal ouvert), mais seule une compilation réelle donne
une garantie complète.

Impression en **simple face** (`oneside`), comme l'exige le guide ENSIASD.
Sortie : `main.pdf`.

## Mise en page (ENSIASD)

- Times New Roman, 12 pt, interligne 1,5, marges 2,5 cm
- Titres de chapitre : nouvelle page, 16 pt, MAJUSCULES, gras, alignés à
  droite, espacement après 54 pt
- Thème du stage en page de garde : 20 pt
- Paragraphes numérotés I, I.1, I.1.1
- Figures : légende en dessous, italique, 11 pt, numérotées par chapitre
- Tableaux : légende au-dessus, 11 pt, numérotés par chapitre
- Numéros de page en bas à droite, à partir de l'introduction générale
- Bibliographie par ordre d'apparition dans le texte

## Palette

Fond blanc, texte quasi noir. Un bleu clair sert d'accent principal (titres
de chapitre, filets, liens, en-têtes de tableau). Un rouge sang foncé est
utilisé de façon discrète, en second accent, pour les points d'attention et
les limites — cohérent avec le sujet du rapport, qui documente
explicitement ses propres limites plutôt que de les dissimuler.

## Contenu généré à partir du dépôt réel

Les chiffres cités dans le rapport (101 tests, 30 entrées CWE, 33
vulnérabilités trouvées sur `sample_vuln_app`, etc.) ont été vérifiés
directement dans le code source et par exécution réelle de l'outil au
moment de la rédaction — pas inventés. Si le code évolue par la suite
(nouveaux tests, nouvelles entrées CWE), ces chiffres devront être
recalculés avant l'impression finale.

## Contenu de la révision (deuxième passe)

Cette version renforce trois points par rapport à la première :

- **Semgrep présenté comme l'outil central**, et non comme un outil parmi
  trois équivalents — un chapitre II restructuré explique d'abord ce
  qu'est le SAST en langage simple (analogie du correcteur orthographique),
  puis pourquoi Semgrep en particulier a été retenu, avant de présenter
  Trivy et Gitleaks comme deux compléments plus ciblés.
- **Moins de code, plus de figures.** Les deux extraits de code les moins
  utiles à un lecteur non technicien (`route()`, `ALL_SCANNERS`) ont été
  retirés du corps du texte et remplacés par des schémas ; seul l'extrait
  sur l'identité d'un `Finding` (`fingerprint`) reste dans le corps, parce
  que c'est la seule règle du projet qu'il est plus clair de montrer en
  code que de décrire en mots. Deux figures ont été ajoutées (principe du
  SAST, schéma d'intersection du routage), portant le total à 12 figures.
- **Encadrés « En clair »** ajoutés après les explications les plus
  techniques (routage, identité des vulnérabilités, exclusions), pour
  résumer chaque mécanisme en une ou deux phrases simples.

