import csv

def calculer_moyenne_deuxieme_colonne(fichier_csv):
    with open(fichier_csv, mode='r', newline='', encoding='utf-8') as fichier:
        lecteur_csv = csv.reader(fichier)
        total = 0
        compteur = 0

        for ligne in lecteur_csv:
            try:
                valeur = float(ligne[1])  # Convertir la valeur de la deuxième colonne en float
                total += valeur
                compteur += 1
            except (ValueError, IndexError):
                # Ignorer les lignes qui ne peuvent pas être converties ou qui n'ont pas assez de colonnes
                continue

        if compteur == 0:
            return None  # Éviter la division par zéro si aucune valeur valide n'est trouvée
        return total / compteur

# Exemple d'utilisation
fichier_csv = 'SP/1000simulation/file_time2.csv'  # Remplacez par le chemin de votre fichier CSV
moyenne = calculer_moyenne_deuxieme_colonne(fichier_csv)
if moyenne is not None:
    print(f"La moyenne de la deuxième colonne est : {moyenne}")
else:
    print("Aucune valeur valide trouvée dans la deuxième colonne.")