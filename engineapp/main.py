#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
from validator import valid_month, valid_day, valid_year

form="""
<p> What's your birthday?</p>
<form method="post">
    <label>Month
        <input type="text" name="month">
    </label>
    <label>Day
        <input type="text" name="day">
    </label>
    <label>Year
        <input type="text" name="year">
    </label>
    <input type="submit">
</form>
"""

class MainHandler(webapp2.RequestHandler):
    def get(self):
        # self.response.headers['Content-Type'] = 'text/plain'
        self.response.write(form)

    def post(self):
        user_month = valid_month(self.request.get("month"))
        user_day = valid_day(self.request.get("day"))
        user_year = valid_year(self.request.get("year"))
        print(user_month, user_day,user_year)
        # if (user_month and user_day and user_year):
        #     self.response.write("You submitted the value of " + user_month + " " + user_day + "," + user_year)
        if (user_month and user_day and user_year):
            self.response.write("You submitted the value of " + str(user_month) + " " + str(user_day) + "," + str(user_year))
        else:
            self.response.write(form)

class FormHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        # self.response.write(q)
        # useful for debug:
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(self.request)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/formTest', FormHandler)
], debug=True)
