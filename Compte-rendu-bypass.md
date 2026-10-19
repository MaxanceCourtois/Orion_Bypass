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
* Les données du PE (.text, .data, .rdata, dont l’IAT, .rsrc, .reloc, etc.)
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

Une fois le point d’entrée récupéré, lorsque le processeur décide de gérer le processus il récupère les données nécessaires à l’exécution à partir de valeurs enregistrées par le thread (valeurs de registres, pile d’exécution, prochaine instruction à exécuter)
Le processeur exécute les instructions binaires contenues dans .text. Ce dernier interagit avec les autres sections du PE, notamment pour récupérer les adresses de fonctions de DLL dans l’IAT, ou pour interagir avec le Heap ou le Stack créé pour le processus.




## 🏗️ Architecture du Packer / Loader

L'intérêt majeur du loader est l'exécution **Fileless** (chargement direct en RAM), évitant ainsi l'analyse statique du fichier sur le disque.

* **Outil utilisé** : Fork `LoadThat-PEAndAssembly` (ProcessusT).
* **Avantage** : génère dynamiquement un custom loader qui embarque l'exécutable initial, l'obfusque et l'exécute directement en RAM
* **Optimisation** : Utilisation d'opérations arithmétiques pour obfusquer le PE, et changement de noms de variables et de fonctions de manière aléatoire, à chaque compilation.

### Fonctionnement technique
Le loader se substitue au *Windows Loader* standard pour minimiser les interactions avec l'OS et éviter les *hooks* de l'antivirus :

1.  **Chiffrement par Chunks** : Le script Python (Packer) divise l'exécutable en segments chiffrés via 10 à 20 opérations XOR avec des clés dynamiques (différentes à chaque compilation).
2.  **Randomisation** : Obfuscation des noms de variables et de fonctions dans le code source C++ généré.
3.  **Gestion de la Mémoire** : Allocation d'espace via `VirtualAlloc` et copie des chunks déchiffrés dans un buffer via `memcpy`.
4.  **Résolution d'IAT (Import Address Table)** : Le loader résout lui-même les DLL et adresses de fonctions nécessaires (Reflective DLL Injection) pour éviter les appels suspects durant le chargement initial.

---

## 🔐 Obfuscation avancée (OLLVM)

Pour renforcer la robustesse, nous intégrons des passes **OLLVM (Obfuscated LLVM)** au niveau de l'IR (Intermediate Representation) via le compilateur `clang`.

* **Outil utilisé** : Fork `ollvm16` (wwh1004), fork `llvm-project` (llvm), ce dernier étant un outil qui permet de construire et gérer des compilateurs.
* **Avantage** : Rend le binaire illisible par désassemblage et efface les signatures statiques.
* **Optimisation** : Utilisation de flags spécifiques pour cibler les fonctions critiques et limiter l'impact sur les performances.

### Fonctionnement technique

ollvm utilise des fonctions d'obfuscation, qui ont dues être intégrées dans les librairies de llvm-project. Quelques exemples de ces fonctions :

1. **Control Flow Flattening (CFF)** : « aplatit » les boucles et les conditions dans un while contenant un switch central, contrôlé par une variable d’état (on entre dans une condition selon la valeur de la variable d’état, qui est modifiée à chaque tour de boucle selon la condition remplie)
2. **Bogus Control Flow (BCF)** : ajoute du junk code dans le code source, *i.e* du code inutile qui va donc modifier le binaire pour aucune opération effectuée
3. **Substitution d’instructions** : transforme des opérations mathématiques simples en des séquences d’opérations logiques complexes (avec des XOR, AND, NOT)

## Commandes d'utilisation

**1. Génération du code source obfusqué (Python) :**
```bash
python3 encrypt_pe.py <TARGET_MALWARE.exe> <OUTPUT_CODE.cpp>
# Exemple : python3 encrypt_pe.py mimikatz.exe encrypted_pe.cpp
```
**2. Compilation du loader avec flags d'obfuscation :**
```bash
# Exemple de compilation avec Control Flow Flattening (-fla) et Bogus Control Flow (-bcf)
./clang++ -mllvm -fla -mllvm -bcf \
    -target x86_64-pc-windows-gnu \
    -I /path/to/includes \
    -L /path/to/libs \
    -static encrypted_pe.cpp -o orion.exe \
    -Wl,--start-group -lstdc++ -lpthread -lmingw32 -lgcc -lgcc_eh -Wl,--end-group
# Exemple (selon le système de fichiers de ma vm) :
../../../../../../../home/courtoma/llvm-project/build/bin/clang++ \		
    -target x86_64-pc-windows-gnu \
    -I usr/lib/gcc/x86_64_w64-mingw32/14-posix/include/c++ \
    -I usr/lib/gcc/x86_64_w64-mingw32/14-posix/include/c++/ x86_64_w64-mingw32 \
    -L usr/lib/gcc/x86_64_w64-mingw32/14-posix \
    -L usr/ x86_64_w64-mingw32/lib  \		
    -static encrypted_pe.cpp -o orion.exe \
    -Wl,--start-group -lstdc++ -lpthread -lmingw32 -lgcc -lgcc_eh -Wl,--end-group

``` 
**à noter :** les flags d'obfuscation ne sont pas à rajouter puisque le packer l'intègre directement dans le code source du loader

## 🛠️ Phase de tests 

En téléversant notre loader sur un site internet et en récupérant celui-ci depuis un vm cible avec Windows Defender activé, on teste :
![Capture d'écran Exécution de Mimikatz](img/execution.png)


Le résultat nous donne une exécution de mimikatz (certes lente car mimikatz est énergivore en ressources) qui n’est pas détectée par le Windows Defender.

On vérifie aussi avec VirusTotal sa performance :
![Capture d'écran VirusTotal](img/virtotal.png)

