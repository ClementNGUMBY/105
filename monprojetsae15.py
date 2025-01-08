import csv
import webbrowser
import matplotlib.pyplot as plt
import numpy as np



#ouvrir le fichier "fichieratraiter.txt"
fichier=open("DumpFile.txt", "r")

#création des listes = Créer des listes pour remplir chacune d'elles avec les données appropriées dans la capture de paquets tcpdump.
ipsr=[]
ipde=[]
longueur=[]
flag=[]
seq=[]
heure=[]

      # créer des compteurs
#compteur du nombre de flag [P] = counter for flag [P] number
flagcounterP=0
#compteur du nombre de flag [S] = counter for flag [S] number
flagcounterS=0
#compteur du nombre de flag [.] = counter for flag [.] number
flagcounter=0
#compteur des trames échangés = counter for number of frames  exchanged on network
framecounter=0
#compteur request = counter for the number of requests
requestcounter=0
#compteur reply = counter for number of replies
replycounter=0
#compteur sequence = sequences counter
seqcounter=0
#compteur acknowledgement = acknowledgments counter
ackcounter=0
#compteur window = windows counter
wincounter=0

for ligne in fichier:
    # make a split with space as delimiter = faire une séparation avec un espace comme délimiteur
    split=ligne.split(" ")
    #delete the hexadecimal blocks and keep only the lines which contain the information
    #supprimez les blocs hexadécimaux et conservez uniquement les lignes contenant les informations.
    if "IP" in ligne :
    #filling the flag list
    #remplissage de la liste drapeau    
        framecounter+=1
        if "[P.]" in ligne :
            flag.append("[P.]")
            flagcounterP+=1
        if "[.]" in ligne :
            flag.append("[.]")
            flagcounter+=1
        if "[S]" in ligne :
            flag.append("[S]")
            flagcounterS+=1
        #filling the seq list
        #remplir la liste seq
        if "seq" in ligne :
            seqcounter+=1
            seq.append(split[8])
        #counting windows
        ##comptage des fenêtres
        if "win" in ligne :
            wincounter+=1
        #counting acks 
        #comptage d'accusé de réception
        if "ack" in ligne:
            ackcounter+=1