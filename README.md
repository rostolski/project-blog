<b>('/blog/?', BlogFront)</b>: Main blog page.  Initially loads with just the header until the user logs in or signs up for an account. Once the user has logged in all blog posts are loaded.

<b>('/blog/post/([0-9]+)', LoadPost)</b>: When clicking on create new post, this site will eventually load and house the URL with the blog post ID.

<b>('/blog/comment/([0-9]+)', LoadComment)</b>: When creating a comment this template is used.

<b>('/blog/newpost', NewPost)</b>: When selecting create new post, this template is used to fill in the details to create the new post.

<b>('/blog/newcomment', NewComment)</b>: Within a single blog post view, you view all existing comments and have the ability to create new comments.  When creating a new comment, this template/link is loaded.

<b>('/blog/editpost', EditPost)</b>: Used to Edit a Blog Post, referenced within the single blog posting view.

<b>('/blog/editcomment', EditComment)</b>: Used to Edit a Blog Comment, referenced within the single blog posting view.

<b>('/blog/deletepost', DeletePost)</b>: Used to Delete a Blog Post, referenced within a single blog posting.

<b>('/blog/deletecomment', DeleteComment)</b>: Used to Delete a Blog Comment, referenced within a single blog comment.

<b>('/signup', Register)</b>: Found on the header in the top right.

<b>('/login', Login)</b>: Found on the header in the top right.

<b>('/logout', Logout)</b>: Found on the header in the top right

<b>('/welcome', Welcome)</b>: Loads after a user logs in.
