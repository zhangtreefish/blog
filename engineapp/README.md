# A Simple Blog App Built with Google App Engine
### Explore my app at [here](https://3-dot-default-dot-gaejinjablog.appspot.com/), or [here](https://gaejinjablog.appspot.com/) for the version with Chinese UI.
{baseUrl} = https://gaejinjablog.appspot.com from here on.
## Features:
--Front page that lists 10 recent blog posts for all visitors and own posts
  for logged-in user: {baseUrl}/welcome or {baseUrl}<br />
--A form to submit new entries: {baseUrl}/newpost<br />
--Blog posts have their own page: {baseUrl}/post/<post_id>.<br />
--A post can be modified by its author: {baseUrl}/deletepost, or
    {baseUrl}/post/<post_key_st>/edit<br />
--A logged in user can comment on a post: {baseUrl}/post/<post_key_st>/newcomment<br />
--A logged in user can like others' post: {baseUrl}/post/<post_key_st>/like<br />
--A comment can be modified by its author: {baseUrl}/post/<post_key_st>/deletecomment,
   or {baseUrl}/post/<post_key_st>/comment/<comment_key_st>/edit<br />
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
  and go to localhost:8080
* To run the app with fresh data:`dev_appserver.py . --clear_datastore true`
* To deploy: create a project at Google Cloud Platform, asign
  yourself a role in the project at IAM/Admin tab. To deploy run
 `gcloud app deploy --project <proj-name> -v <version-number>`

## References
1 [webapp2 Building URIs](https://webapp2.readthedocs.io/en/latest/guide/routing.html#guide-routing-building-uris)<br />
2 [deploying a Python App](https://cloud.google.com/appengine/docs/python/tools/uploadinganapp)<br />
3 [quickstart](https://cloud.google.com/appengine/docs/python/quickstart)<br />
4 [reset local datastore  dev_appserver.py [app directory] --clear_datastore true](http://stackoverflow.com/questions/1010573/how-do-i-delete-all-entities-from-my-local-google-app-engine-datastore)<br />
5. [ancestors and parent](https://cloud.google.com/appengine/docs/python/ndb/creating-entity-keys)<br />
6. [migration from db to ndb](https://cloud.google.com/appengine/docs/python/ndb/db_to_ndb)<br />
7. [on the convenience a cookie offers and when not to use it](https://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice/)<br />
8. [Programming Google App Engine with Python Build and Run Scalable Python
By Dan Sanderson](https://books.google.com/books?id=4BIDCgAAQBAJ&pg=PA214&lpg=PA214&dq=required%3DTrue+not+enforced+by+ndb&source=bl&ots=lmJklvVdvb&sig=AcEdzFGzanzajz9F23-HEp_5Y8w&hl=en&sa=X&ved=0ahUKEwjmmtrvs5zRAhUjwFQKHT7zBIAQ6AEIKDAC#v=onepage&q=required%3DTrue%20not%20enforced%20by%20ndb&f=false)<br />
9. [set default value to textarea tag](http://stackoverflow.com/questions/6007219/how-to-add-default-value-for-html-textarea)<br />
10. [exceptions of ndb datastore](https://cloud.google.com/appengine/docs/python/ndb/exceptions)<br />
11. [calculate list length in jinja2](http://stackoverflow.com/questions/24163579/length-of-string-in-jinja-flask)<br />
12. [create a modal in jinja2](http://stackoverflow.com/questions/21944735/what-is-the-data-target-attribute-in-bootstrap-3)<br />
13. [modal example](http://getbootstrap.com/javascript/#modals-examples)<br />
14. [include in jinja](http://jinja.pocoo.org/docs/dev/templates/#import)<br />
15. [css validator](https://jigsaw.w3.org/css-validator/validator)<br />
16. [http://pep8online.com]<br />
17. [jinja macro](http://stackoverflow.com/questions/9404990/how-to-pass-selected-named-arguments-to-jinja2s-include-context)<br />
18. [set unique modal ids](http://stackoverflow.com/questions/40937631/modals-created-in-jinja-conditional-statement-are-all-showing-the-same-data)<br />
19. [ProtocolBufferDecodeError](http://stackoverflow.com/questions/20731851/how-to-properly-handle-wrong-urlsafe-key-provided)<br />
20. [decorator for webapp2](https://discussions.udacity.com/t/final-project-trouble-separating-handlers-and-classes-into-their-own-packages/188462/5)<br />
21. [*args and **kwargs in decorators](http://stackoverflow.com/questions/1965607/how-can-i-pass-a-variable-in-a-decorator-to-functions-argument-in-a-decorated-f)<br />
22. [Modeling Entity Relationships](https://cloud.google.com/appengine/articles/modeling#one-to-many)<br />
23. [use http verb delete-not other verbs-for delete](http://www.drdobbs.com/web-development/restful-web-services-a-tutorial/240169069?pgno=2)<br />
24. [create-index to solve the missing index error in deployment](http://stackoverflow.com/questions/37077734/app-engine-needindexerror-no-matching-index-found)<br />
25. [splitting traffic: How Requests are Routed](https://cloud.google.com/appengine/docs/python/how-requests-are-routed)<br />
26. [set version3 branch as master](http://stackoverflow.com/questions/2862590/how-to-replace-master-branch-in-git-entirely-from-another-branch)
27. [over-riding webapp2.RequestHandler.__init__()](http://webapp2.readthedocs.io/en/latest/guide/handlers.html)