# A Simple Blog App Built with Google App Engine
### Explore my app at [here](http://gaejinjablog.appspot.com/blog)
{baseUrl} = http://gaejinjablog.appspot.com/blog from here on.
## Features:
--Front page that lists blog posts: {baseUrl}/welcome<br />
--A form to submit new entries: {baseUrl}/newpost<br />
--Blog posts have their own page: {baseUrl}/post/<post_id>.<br />

--A signup form that validates inputs and displays error(s):
  {baseUrl}/signup; upon success the user is directed to the
  welcome page;<br />
-- If a user visits without being signed in (i.e. having a cookie),
   the user is redirected to the signup page<br />
-- Passwords stored securely as salted hash<br />

-- A login form that validates inputs and displays error(s):
   {baseUrl}/login; on success directed to the same welcome page<br />

-- A logout form that validates inputs and displays error(s):
   {baseUrl}/logout; on success the cookie is cleared and user is
   redirected to the signup page.<br />

## How to run this app from your machine

* Run git clone https://github.com/zhangtreefish/blog.git
* Run inside the directory engineapp:`dev_appserver.py . `
  and go to localhost:8080/blog
* To run the app with fresh data:`dev_appserver.py . --clear_datastore true`
* To deploy: create a project at Google Cloud Platform, asign
  yourself a role in the project at IAM/Admin tab. To deploy run
 `gcloud app deploy`

## References
1 [webapp2 Building URIs](https://webapp2.readthedocs.io/en/latest/guide/routing.html#guide-routing-building-uris)
2 [Deploying a Python App](https://cloud.google.com/appengine/docs/python/tools/uploadinganapp)
3 [quickstart](https://cloud.google.com/appengine/docs/python/quickstart)
4 [Reset local datastore  dev_appserver.py [app directory] --clear_datastore true](http://stackoverflow.com/questions/1010573/how-do-i-delete-all-entities-from-my-local-google-app-engine-datastore)
5. [Ancestors and parent](https://cloud.google.com/appengine/docs/python/ndb/creating-entity-keys)
6. [migration from db to ndb](https://cloud.google.com/appengine/docs/python/ndb/db_to_ndb)
7. [On the convenience a cookie offers and when not to use it](https://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice/)
8. [Programming Google App Engine with Python Build and Run Scalable Python
By Dan Sanderson](https://books.google.com/books?id=4BIDCgAAQBAJ&pg=PA214&lpg=PA214&dq=required%3DTrue+not+enforced+by+ndb&source=bl&ots=lmJklvVdvb&sig=AcEdzFGzanzajz9F23-HEp_5Y8w&hl=en&sa=X&ved=0ahUKEwjmmtrvs5zRAhUjwFQKHT7zBIAQ6AEIKDAC#v=onepage&q=required%3DTrue%20not%20enforced%20by%20ndb&f=false)
9. [Set default value to textarea tag](http://stackoverflow.com/questions/6007219/how-to-add-default-value-for-html-textarea)
10. [exceptions of ndb datastore](https://cloud.google.com/appengine/docs/python/ndb/exceptions)
11. [calculate list length in jinja2](http://stackoverflow.com/questions/24163579/length-of-string-in-jinja-flask)
12. [create a modal in jinja2](http://stackoverflow.com/questions/21944735/what-is-the-data-target-attribute-in-bootstrap-3)
13. [modal example](http://getbootstrap.com/javascript/#modals-examples)