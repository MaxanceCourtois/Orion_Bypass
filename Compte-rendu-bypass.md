# Projet Orion : Rapport d'Activité - Équipe Bypass

## 🎯 Objectifs
L'équipe **Bypass** est responsable de la neutralisation des mécanismes d'analyse statique et comportementale des systèmes d'exploitation. L'objectif final est de permettre l'exécution du malware développé par l'équipe *Ransomware* sans détection ni interruption par les solutions de sécurité (Antivirus/EDR).

Dans le cadre de ce Proof of Concept (PoC), nos efforts se sont concentrés sur le contournement de **Windows Defender** pour l'exécution de **Mimikatz** (extraction de credentials et manipulation de privilèges).

---


## 🛠️ Stratégie de Contournement

### Approches Passives (Considérées)
Plusieurs techniques de discrétion ont été étudiées :
* **Chiffrement des communications** : Sécurisation du flux entre le C2 et l'agent.
* **Fonctions Custom** : Implémentation d'une fonction `sleep` personnalisée pour contrer l'accélération de l'horloge (système de sandbox propre à un EDR).

### Approche Retenue : Packer/Loader & Obfuscation LLVM
Pour offrir une solution flexible et universelle, nous avons développé un **Loader de Native PE** couplé à des LLVM passes grâce à l'outil **OLLVM**. Cette méthode permet d'invisibiliser n'importe quel binaire via une simple ligne de commande.

---


## Introduction des outils

Windows Defender est un outil d'analyse statique, conçu pour analyser les fichiers présents dans le disque dur et signaler leur éventuelle dangerosité au kernel de l'OS. Il est souvent couplé à un outil d'Endpoint Detection & Response (EDR), qui s'occupe de l'analyse comportemental d'un fichier, c'est-à-dire lors de son exécution.

Pour pouvoir exécuter le malware développé par l'équipe DevRansomware sur la machine compromise, il faut éviter sa détection statique par Windows Defender, et ainsi empêcher sa suppression du système de fichiers : l'utilisation d'un loader permet de contourner ce problème.

#### Le loader :
L'intérêt du loader est de pouvoir charger un exécutable directement en RAM ("exécution Fileless"), sans aucune présence sur le disque dur, et ainsi éviter l'analyse statique de Windows Defender.

En principe l'exécution d'un fichier se repose sur le Windows Loader, un programme qui interagit directement avec le kernel : il charge le programme en mémoire et ordonne son exécution.
Le custom loader que nous utilisons agit comme un substitut du Windows Loader : il réalise son travail à sa place de façon à interagir le moins possible avec le kernel. On évite ainsi les hooks de outils de détection sur certaines fonctions Windows sensibles, et l'exécutable n'est pas présent en dur.

Ce loader est lui-même généré par un packer, un script Python qui s'occupe d'obfusquer le code source du loader. 
Et pour rendre notre malware encore plus robuste nous avons décidé d'inclure des LLVM passes lors de la compilation, c'est-à-dire des fonctions qui vont obfusquer le code LLVM IR lors de son optimisation.

L'assemblage de ces éléments constitue notre bypass de Windows Defender pour l'exécution d'un malware. 

---


## Plan

1. **Exécuter un programme** : avant de commencer à parler de loader, il faut comprendre les étapes lors de l'exécution d'un programme.
2. **Le custom loader**
3. **Le custom packer**
4. **L'obfuscation LLVM**

---


## 1. Exécuter un programme :
_Résume les étapes lorsqu’on ordonne l’exécution d’un programme_

#### Etape 1 : création de l’environnement d’exécution

Le noyau crée un processus, lui alloue une mémoire virtuelle, et crée un thread initial.

La **mémoire virtuelle** allouée contient : 
* Les données du PE (`.text`, `.data`, `.rdata`, dont l’IAT, `.rsrc`, `.reloc`, etc.)
* Les bibliothèques partagées (DLL comme ntdll.dll, kernel32.dll, etc.)
* Une mémoire dynamique (Heap, si on alloue de la mémoire lors de l’exécution)
* Une pile d’exécution (Stack, avec @retour pour les instructions etc.)
* La table des descripteurs (handle table, qui gère l’accès aux fichiers utilisés par le programme)
* Un token (définit les privilèges d’accès du processus lors de son interaction avec le noyau, pour accéder à des fichiers, appeler d’autres processus, certains syscalls, etc.)
* Le PEB (une structure en mémoire accédée par le loader pendant l’exécution et contenant des modules chargés, des arguments de la ligne de commande, des variables d’environnement, etc.) 

Le **thread initial** est un fil d’exécution qui accompagne le processus. Il sert à enregistrer l’état de l’exécution pour que le processeur puisse prendre le relais avec tous les éléments dont il a besoin. Il est composé :
* D’une pile d’exécution
* De registres
* D’un registre _RIP_ qui pointe vers l’adresse de la prochaine instruction.


#### Etape 2 : activation du loader pour charger le PE en RAM

Lorsqu’on donne l’ordre d’exécution du programme, le noyau configure le registre _RIP_ du thread du processus pour qu’il pointe vers l’instruction chargée d’initialiser le loader, et qui se situe dans la bibliothèque _ntdll.dll_. 
Instructions exécutées (dans l’ordre) par le thread initial pour activer le loader :
* `LdrInitializeThunk` : configure la gestion des exceptions
* `LdrpInitialize` : configure les structures du PEB
* `LdrpInitializeProcess` : mappe les sections du brut binaire du disque vers la mémoire virtuelle (relocaliser les sections du PE), résout les dépendances (i.e : charge les adresses des DLL listées dans l’IAT), applique les permissions de sécurité sur chaque     section

Après cette étape, le thread appelle le point d’entrée de chaque DLL (le thread fait le DLLMain) qui contient des fonctions d’initialisation. 
Une fois fait, le thread récupère l’adresse du point d’entrée du programme via les fonctions du loader. Le registre RIP est modifié pour pointer vers l’adresse du point d’entrée du programme (fonction AdressOfEntryPoint de la ntdll.dll)

Le loader est donc une **séquence d’instructions de la ntdll.dll** (la bibliothèque plus bas niveau, à la frontière entre l’espace accessible par l’utilisateur et le noyau)


#### Etape 3 : exécuter les séquences d’instructions du PE (.text)

Une fois le point d’entrée récupéré, lorsque le processeur décide de gérer le processus il récupère les données nécessaires à l’exécution à partir de valeurs enregistrées par le thread (valeurs de registres, pile d’exécution, prochaine instruction à exécuter).

Le processeur exécute les instructions binaires contenues dans `.text`. Ce dernier interagit avec les autres sections du PE, notamment pour récupérer les adresses de fonctions de DLL dans l’IAT, ou pour interagir avec le Heap ou le Stack créé pour le processus.

---


## 2. Le Custom Loader :

A partir du fonctionnement du Windows Loader, on en déduit qu’un custom loader doit faire exactement le même travail que le Windows Loader. 
Cependant, le custom loader **ne remplace pas** le Windows Loader. On va en fait exécuter le custom loader dans lequel on a intégré notre PE, qui est XORé et dont les noms de variables et fonctions sont obfusqués à chaque compilation. 

Ainsi les étapes sont les suivantes :
* On ordonne l’exécution du custom loader
* Le Windows loader fait son travail, et exécute le custom loader
* Le custom loader s’occupe de loader le vrai exécutable en RAM :
    * Parsing des en-têtes PE (i.e : indications sur le découpage des chunks, leur taille et où les mettre en mémoire) 
    * Allocation mémoire (VirtualAlloc), copie des chunks en mémoire (memcpy)
    * Relocaliser les sections du .reloc (i.e appliquer un delta d’adresses pour faire correspondre les sections aux bonnes adresses)
    * Résoudre les importations : trouver les fonctions dans le DLL du système et écrire leurs adresses dans l’IAT
    * Appeler le point d’entrée du .text (après avoir fait les DLLMain)

L’antivirus/EDR, pour détecter des syscalls suspects (`VirtualAlloc`, etc), place des hooks dans la `ntdll.dll`, où sont appelées ces fonctions (i.e des jumps qui redirigent vers une DLL de l’EDR pour analyser l’appel de la fonction demandée, i.e inspection des arguments passés à la fonction, analyse de la pile d’appel pour retracer d’où provient l’appel) pour kill le processus en cas de comportement suspect.

Pour contourner l’antivirus/EDR, le loader récupère sur le disque dur la `ntdll.dll` qui n’a pas été hookée par l’EDR, et écrase celle située dans la mémoire virtuelle du processus avec celle qu’il a récupérée.
On peut également obfusquer les chunks du binaire du PE grâce à du XOR et des changements de nom de fonctions/variables aléatoires, pour éviter que l’antivirus ne détecte sa présence dans le loader.

---


## 3. Le Custom Packer :

Pour rappel, la charge utile (le PE) est exécutée directement en mémoire grâce à un **loader**. Ce loader est généré par un **packer**, un script Python qui s’occupe d’obfusquer le code source du loader. 
Ce que gère concrètement le packer :
* Il divise l’exécutable initial en chunks, et effectue entre 10 et 20 opérations XOR pour les chiffrer. Le script permet d’avoir un loader dynamique : à chaque compilation les clés de chiffrement sont différentes.
* Il randomise également les noms des variables et des fonctions du loader de manière aléatoire à chaque compilation.

En résumé, le packer (i.e le script Python) génère le code C++ du loader à partir de la charge utile `.exe`. 

Or en théorie les règles d’analyse statiques mise en place par les analyseurs bloqueraient le fichier du loader avant qu’il ne puisse exécuter le PE en mémoire.
Mais grâce aux opérations du packer sur les noms de fonctions et de variables aléatoires, et le PE obfusqué, les analyseurs sont incapables de repérer le loader.

---


## 4. L'Obfuscation LLVM :

LLVM est un environnement intermédiaire lors de la compilation d’un fichier, utilisé en complément des compilateurs (comme `clang`). Le rôle de cet outil est de **créer un code intermédiaire** (appelé LLVM IR, universel à tous les environnements d’exécution) obtenu à partir de la compilation, de l’**optimiser**, puis de **générer le code binaire** à partir de ce code (selon l’environnement d’exécution, i.e les spécificités du processeur et du système d’exploitation cible).

L’obfuscation LLVM est une modification de l’infrastructure de LLVM, conçue pour brouiller intentionnellement le code machine généré. Son but est de rendre l’analyse et le fonctionnement statique du programme incompréhensible aux yeux d’un humain ou d’un outil de sécurité, tout en conservant son comportement.

L’optimisation du code se fait grâce à des **« LLVM passes »**. L' obfuscation LLVM permet concrètement de détourner l’étape d’optimisation du code intermédiaire. C’est ce que fait précisément l’outil ollvm16, en y injectant ses propres « LLVM passes » comme :
* Control Flow Flattening (FLA) : « aplatit » les boucles et les conditions dans un while contenant un switch central, contrôlé par une variable d’état (on entre dans une condition selon la valeur de la variable d’état, qui change à chaque tour de boucle)
* Bogus Control Flow (BCF) : ajoute du junk code et des instructions inutiles (branchements, équations complexes…). Le code légitime est noyé au milieu du code « mort »
* Substitution d’instructions (SUB) : transforme des opérations mathématiques simples en des séquences d’opérations logiques complexes (avec des XOR, AND, NOT)


#### Comment sont appliquées ces obfuscations ?
Par l’ajout d’attributs dans le code source `.cpp` (par ex :  `__attribute((annotate("fla")))` ). Lors de la compilation, le compilateur conserve ce string comme une étiquette dans l’arbre syntaxique abstrait (AST) de la fonction. 
Lors de la génération du code intémerdiaire, les étiquettes sont converties par le compilateur en métadonnées LLVM.
Lors de l’optimisation du code par les LLVM passes, chaque fonction est examinée par chaque passe LLVM, et à ce moment-là LLVM vérifie si la fonction possède l’étiquette de la passe dans ses métadonnées (en l’occurrence, lorsqu’une passe d’obfuscation examine une fonction qui contient `__attribute((annotate("fla")))`, elle applique la passe à cette fonction, sinon elle ne fait rien sur celle-ci)

#### Objectifs de l’utilisation de LLVM passes :
* **Pénalité de performance :** le code mort doit réellement être exécuté. Le programme s’exécute beaucoup plus lentement, pratique pour l’évasion des sandboxs créées par les EDR 
* **Résistance au reverse engineering :** un décompilateur produira un code totalement illisible
* **Destruction des signatures :** les algorithmes d’obfuscation génère un code machine différent à chaque compilation. Les suites d’octets originellement connues par les analyseurs statiques (i.e les signatures statiques) ne le seront pas ici 

---


## En résumé : que fait conrètement l'outil ?

**_Première étape :_** génération du loader obfusqué à partir du script Python (le packer)

**_Deuxième étape :_** Compilation du loader comprenant la charge utile, ainsi que toutes les bibliothèques nécessaires à l’exécution du fichier sous n’importe quel OS.

**_Troisième étape :_** Application des LLVM passes lors de l’optimisation du code IR pour l’obfusquer, et ainsi supprimer les signatures statiques et ralentir l’analyse lors de la décompilation.

---


## En résumé : comment utiliser l'outil ? 

**1. Génération du code source obfusqué (Python) :**
```bash
python3 encrypt_pe.py <TARGET_MALWARE.exe> <LOADER_CODE.cpp>
# Exemple : python3 encrypt_pe.py mimikatz.exe encrypted_pe.cpp
```
**2. Compilation du loader avec flags d'obfuscation :**
```bash
# Simplifié
clang++ <LOADER_SOURCE.cpp> -o <LOADER_MALWARE.exe> 
# Exemple complet 
    /home/user/llvm-project/build/bin/clang++ \		
    -target x86_64-pc-windows-gnu \
    -I usr/lib/gcc/x86_64_w64-mingw32/14-posix/include/c++ \
    -I usr/lib/gcc/x86_64_w64-mingw32/14-posix/include/c++/ x86_64_w64-mingw32 \
    -L usr/lib/gcc/x86_64_w64-mingw32/14-posix \
    -L usr/ x86_64_w64-mingw32/lib  \		
    -static encrypted_pe.cpp -o orion.exe \
    -Wl,--start-group -lstdc++ -lpthread -lmingw32 -lgcc -lgcc_eh -Wl,--end-group

``` 
**à noter :** les flags d'obfuscation ne sont pas à rajouter puisque le packer l'intègre directement dans le code source du loader
**à noter :** les options sont détaillées plus bas dans "Utilisation de MSYS et MinGW"

---

### Installations et configurations 
_grâce au gestionnaire de paquets winget_

**Git :** pour cloner les projets llvm-project, ollvm16, mimikatz.
**CMake :** génère des fichiers de configuration pour des systèmes de construction de logiciel (compilateurs dans notre cas). Permet à partir d’un fichier de configuration CMakeLists.txt, de générer le Makefile pour automatiser la compilation dans un logiciel.
**Python :** pour l'exécution de scripts Python (notre packer)
**Visual Studio Build Tools 2022 :** Outils de dev C++. Fournit compilateur, editeur de liens, et SDK Windows (bibliothèque de fichiers comme windows.h)
**MSYS2 :** plateforme logicielle pour émuler env Unix sous Windows
**MinGW-w64 GCC :** conpilation GNU installée via MSYS2. Fournit les bibliothèques standards à clang lorsqu’on utilise GNU au lieu de Windows

---


### Utilisation de MSYS2 et MinGW :

Outils qui permettent de porter des logiciels Unix sous Windows. L’utilisation de MinGW simule un environnement Unix lors de la compilation. Cela permet entre eux de résoudre les problématiques d’interopérabilité (un fichier compilé avec MinGW sera exécutable sur un environnement Windows ou Unix).

Praticité :
* Déploiement sans dépendance : MinGW intègre la bibliothèque msvcrt.dll dans le programme (native à toutes les versions de Windows, elle est nécessaire pour exécuter un programme sous Windows) 
* Cross-compilation : MinGW permet par ex de générer un fichier exe compatible Windows à partir d’une compilation sur Linux
* Le lien avec les autres outils : llvm et ollvm sont conçus pour le monde Unix

Performances :
* MinGW génère un binaire plus léger (donc rapide) que le compilateur Microsoft de base (MSVC)
* Meilleure gestion de l’option `--static` (qui permet de forcer l’intégration de tous les éléments nécessaires à l’exécution dans le fichier `.exe` final).

L’utilisation de MinGW se fait lors de la compilation, en intégrant des options à la ligne de commande. 

`-target x86_64-pc-windows-gnu` : ordonne au compilateur clang de générer un binaire déstiné à un processeur 64bits, tournant sur Windows, et respectant l’ABI de GNU (ie on bascule sur MinGW au lieu de MSVC)

`-I <chemin>` : _include directory :_ indique au compilateur les dossiers supplémentaires dans lesquels il doit chercher des fichiers d’en-tête (comme <stdio.h> par ex)

`-L <chemin>` : _library directory :_ indique à l’éditeur de liens où trouver les bibliothèques binaires précompilées (une fois le code compilé le linker lie le programme aux fonctions natives de l’OS, d’où le besoin de les inclure pour la portabilité)

`-Wl,--start-group -lstdc++ -lpthread -lmingw32 -lgcc -lgcc_eh -Wl,--end-group` : _spécifique pour le linker :_ on lui lie manuellement les bibliothèques dont il a besoin, et on le force à lire en boucle les bibliothèques jusqu’à ce que toutes les dépendances croisées (i.e dépendance circulaire : la bib A a besoin de la bib B, et la bib B a besoin de la bib A) soient résolues

--- 


## 🛠️ Phase de tests 

En téléversant notre loader sur un site internet et en récupérant celui-ci depuis un vm cible avec Windows Defender activé, on teste :
![Capture d'écran Exécution de Mimikatz](img/execution.png)


Le résultat nous donne une exécution de mimikatz (certes lente car mimikatz est énergivore en ressources) qui n’est pas détectée par le Windows Defender.

On vérifie aussi avec VirusTotal sa performance :
![Capture d'écran VirusTotal](img/virtotal.png)

