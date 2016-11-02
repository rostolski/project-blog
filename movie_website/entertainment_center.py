# Lesson 3.4: Make Classes
# Mini-Project: Movies Website

# In this file, you will define instances of the class Movie defined
# in media.py. After you follow along with Kunal, make some instances
# of your own!

# After you run this code, open the file fresh_tomatoes.html to
# see your webpage!

import media
import fresh_tomatoes

rogue_one = media.Movie("Rogue One: A Star Wars Story",
                        "In a time of conflict, a group of unlikely heroes band together on a misson to steal the plans to the Death Star, the Empire's ultimate weapon of destruction.",
                        "http://img.lum.dolimg.com/v1/images/la_poster_dfe5333c.jpeg?region=0%2C0%2C1000%2C1481&width=768",
                        "https://www.youtube.com/watch?v=frdj1zb9sMY")

#print (toy_story.storyline)
#toy_story.show_trailer()

dr_strange = media.Movie("Doctor Strange",
                    "A former neurosurgeon, Strange serves as the Sorcerer Supreme, the primary protector of Earth against magical and mystical threats.",
                    "http://static.srcdn.com/slir/w691-h1023-q90-c691:1023/wp-content/uploads/Doctor-Strange-Comic-Con-Poster.jpg",
                    "https://www.youtube.com/watch?v=HSzx-zryEgM")

civil_war = media.Movie("Captain America: Civil War",
                        "Political pressure mounts to install a system of accountability when the actions of the Avengers lead to collateral damage.",
                        "http://www.eonline.com/eol_images/Entire_Site/201627/rs_634x940-160307074539-634.captain-america-civil-war-poster-chris-evans-robert-downey-jr.3716.jpg",
                        "https://www.youtube.com/watch?v=dKrVegVI0Us")

deadpool = media.Movie("Deadpool",
                        "Wade Wilson (Ryan Reynolds) is a former Special Forces operative who now works as a mercenary. His world comes crashing down when evil scientist Ajax (Ed Skrein) tortures, disfigures and transforms him into Deadpool.",
                        "http://www.ew.com/sites/default/files/i/2015/12/13/ew-deadpool-poster.jpg",
                        "https://www.youtube.com/watch?v=9vN6DHB6bJc")

the_force = media.Movie("Star Wars: The Force Awakens",
                        "Thirty years after the defeat of the Galactic Empire, Han Solo (Harrison Ford) and his young allies face a new threat from the evil Kylo Ren (Adam Driver) and the First Order.",
                        "http://t0.gstatic.com/images?q=tbn:ANd9GcT6nGxj1D4P-9EiVSY32sb6Ql-XQrbeK5FgM37UI6QxcZwfcfVw",
                        "https://www.youtube.com/watch?v=sGbxmsDFVnE")

beyond = media.Movie("Star Trek: Beyond",
                    "A surprise attack in outer space forces the Enterprise to crash-land on a mysterious world.",
                    "http://screenrant.com/wp-content/uploads/star-trek-beyond-poster-kirk.jpg",
                    "https://www.youtube.com/watch?v=bzD8H6o1awQ")

movies = [rogue_one, dr_strange, civil_war, deadpool, the_force, beyond]
fresh_tomatoes.open_movies_page(movies)
#print (avatar.storyline)


#avatar = media.Movie()



#print(media.Movie.VALID_RATINGS)
