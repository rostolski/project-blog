('/blog/?', BlogFront): Main blog page
('/blog/post/([0-9]+)', LoadPost): 
('/blog/comment/([0-9]+)', LoadComment),
('/blog/newpost', NewPost),
('/blog/newcomment', NewComment),
('/blog/editpost', EditPost),
('/blog/editcomment', EditComment),
('/blog/deletepost', DeletePost),
('/blog/deletecomment', DeleteComment),
('/signup', Register),
('/login', Login),
('/logout', Logout),
('/welcome', Welcome),
