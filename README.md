<b>('/blog/?', BlogFront)</b>: Main blog page.  Initially loads with just the header until the user logs in or signs up for an account. Once the user has logged in all blog posts are loaded

<b>('/blog/post/([0-9]+)', LoadPost)</b>: 
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
