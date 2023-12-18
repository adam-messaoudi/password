import re
import hashlib

# Fonction qui vérifie si le mot de passe satisfait les critères de sécurité
def verify_password(password):
    # Liste des conditions que le mot de passe doit remplir
    conditions = [
        lambda s: len(s) >= 8,  # Longueur minimale de 8 caractères
        lambda s: any(c.isupper() for c in s),  # Au moins une lettre majuscule
        lambda s: any(c.islower() for c in s),  # Au moins une lettre minuscule
        lambda s: any(c.isdigit() for c in s),  # Au moins un chiffre
        lambda s: any(c in '!@#$%^&*' for c in s)  # Au moins un caractère spécial
    ]

    # Vérifie si toutes les conditions sont remplies pour le mot de passe donné
    return all(cond(password) for cond in conditions)

# Fonction principale du programme
def main():
    while True:
        user_password = input("Choisissez un mot de passe : ")  # Demande à l'utilisateur de saisir un mot de passe
        
        # Vérifie si le mot de passe est valide
        if verify_password(user_password):
            hashed_password = hash_password(user_password)  # Hache le mot de passe
            print(f"Mot de passe haché avec SHA-256 : {hashed_password}")  # Affiche le mot de passe haché
            break  # Sort de la boucle si le mot de passe est valide
        else:
            print("Le mot de passe ne respecte pas les critères de sécurité. Veuillez en choisir un autre.")  # Message si le mot de passe ne respecte pas les critères

# Fonction pour hacher le mot de passe avec l'algorithme de hachage SHA-256
def hash_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()  # Hachage du mot de passe
    return hashed  # Renvoie le mot de passe haché

if __name__ == "__main__":
    main()  # Appel de la fonction principale si le script est exécuté directement
