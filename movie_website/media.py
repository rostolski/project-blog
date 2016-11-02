# Lesson 3.4: Make Classes
# Mini-Project: Movies Website

# In this file, you will define the class Movie. You could do this
# directly in entertainment_center.py but many developers keep their
# class definitions separate from the rest of their code. This also
# gives you practice importing Python files.

import webbrowser

class Movie():
    # This class provides a way to store movie related information
    # VALID_RATINGS = ["G", "PG", "PG-13", "R"]

    def __init__(self, movie_title, movie_storyline, poster_image, trailer_youtube):
        # initialize instance of class Movie
        #Input: entertainment_center.py calls class media.Movie to set individual values for each movie
        #Output: This is sent back defined into each movie title and then used later in fresh_tomatoes.py to display on the website
        self.title = movie_title
        self.storyline = movie_storyline
        self.poster_image_url = poster_image
        self.trailer_youtube_url = trailer_youtube

    #def show_trailer(self):
        #Opens a new browser to play a trailer - This code is not required of the fresh_tomatoes site, but can be used to test independent functionality
    #    webbrowser.open(self.trailer_youtube_url)
