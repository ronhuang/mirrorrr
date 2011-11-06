# -*- coding: utf-8 -*-
"""
    tipfy.core.model.acl
    ~~~~~~~~~~~~~~~~~~~~

    Access Control List storage system. Ported from Solar's Access and Role
    classes: http://solarphp.com.

    This is used to store permissions for anything that requires some
    level of restriction, like models or handlers. Access permissions
    can be grouped in roles for convenience, so that a new user can be assigned
    to a role directly instead of having all his permissions defined manually.
    Individual access permissions can then override or extend the role
    permissions.

    For example, create a 'admin' role with full access and assign users to it:

    # Create a full-access rule and assign it to the 'admin' role..
    access = Access(mode='role', name='admin', class_name='*', action_name='*',
        flag=True)
    access.put()

    # Assign users 'user_1' and 'user_2' to the 'admin' role.
    role = Role(user='user_1', role='admin')
    role.put()
    role = Role(user='user_2', role='admin')
    role.put()

    # Restrict 'user_2' from accessing a specific area, so now access is
    # allowed to everything except this area.
    access = Access(mode='user', name='user_2', class_name='UserAdmin',
        action_name='put', flag=False)
    access.put()

    # Check 'user_2' permission.
    acl = Acl('user_2')
    has_access = acl.has_access(class_name='UserAdmin', action_name='put')

    :copyright: 2009 by tipfy.org.
    :license: BSD, see LICENSE.txt for more details.
"""
from google.appengine.dist import use_library
use_library('django', '1.2')

from google.appengine.ext import db
from google.appengine.api import memcache
import logging

class Access(db.Model):
    """Model to store access permisions to users or roles."""
    # Access mode ('user' or 'role').
    mode = db.StringProperty(required=True)
    # User or role name. The wildcard '*' is used as "catch-all" in
    # 'user' or 'role' modes, and '+' is used with 'user' mode to match
    # all authenticated users.
    name = db.StringProperty(required=True, default='*')
    # The class name.
    class_name = db.StringProperty(required=True, default='*')
    # The action name.
    action_name = db.StringProperty(required=True, default='*')
    # Permission flag: allow or deny access.
    flag = db.BooleanProperty(required=True)
    # Results are ordered by this property.
    position = db.IntegerProperty(required=True, default=1)

    @classmethod
    def _get_rules(cls, mode, name):
        """Fetches and caches an access rule type."""
        key = 'acl.access.%s.%s' % (mode, name)

        # Try to fetch from cache.
        rules = memcache.get(key)
        if rules is not None:
            return rules

        # Not cached, so fetch the rules from datastore.
        entities = cls.all().filter('mode =', mode).filter('name =', name) \
            .order('position').fetch(100)

        # Rebuild the results as a dictionary.
        rules = []
        if entities:
            for entity in entities:
                rules.append({
                    'mode':   entity.mode,
                    'name':   entity.name,
                    'class':  entity.class_name,
                    'action': entity.action_name,
                    'flag':   entity.flag
                })

            # Store in cache.
            if not memcache.add(key, rules):
                logging.error('Memcache set failed.')

        return rules

    @classmethod
    def get_rules(cls, username, roles):
        """Returns all access rules for a given username and roles."""
        # Prepare user list.
        if username:
            # User is authenticated.
            user_list = [username, '*', '+']
        else:
            # User is anonymous.
            user_list = ['*']

        # Prepare role list.
        roles.append('*')

        # Start the access list.
        rules = []
        # Add user rules.
        for name in user_list:
            rules.extend(cls._get_rules('user', name))
        # Add role rules.
        for name in roles:
            rules.extend(cls._get_rules('role', name))

        return rules

    def put(self):
        self.delete_cache()
        super(Access, self).put()

    def delete(self):
        self.delete_cache()
        super(Access, self).delete()

    def delete_cache(self):
        """Deletes the cache for these rules."""
        key = 'acl.access.%s.%s' % (self.mode, self.name)
        memcache.delete(key)


class Role(db.Model):
    """Model to store user roles."""
    # User name assigned to the role.
    user = db.StringProperty(required=True)
    # Role name.
    role = db.StringProperty(required=True)

    @classmethod
    def get_roles(cls, username):
        """Fetches and caches a list of user roles."""
        key = 'acl.role.%s' % (username)

        # Try to fetch from cache.
        roles = memcache.get(key)
        if roles is not None:
            return roles

        # Not cached, so fetch the roles from datastore.
        entities = cls.all().filter('user =', username).fetch(100)

        # Rebuild the results as a simple list.
        if entities:
            roles = [entity.role for entity in entities]
        else:
            roles = []

        # Store in cache.
        if not memcache.add(key, roles):
            logging.error('Memcache set failed.')

        return roles

    def put(self):
        self.delete_cache()
        super(Role, self).put()

    def delete(self):
        self.delete_cache()
        super(Role, self).delete()

    def delete_cache(self):
        """Deletes the cache for this user."""
        key = 'acl.role.%s' % (self.user)
        memcache.delete(key)


class Acl(object):
    """Loads access rules and roles for a given user and provides a centralized
    interface to check permissions."""
    def __init__(self, username):
        """Loads access privileges and roles for a given user."""
        # Load roles.
        if username:
            self.roles = Role.get_roles(username)
        else:
            self.roles = []

        # Load access rules and reverse them - last ones are checked first.
        self.access = Access.get_rules(username, self.roles)
        self.access.reverse()

    def reset(self):
        """Resets the currently loaded access rules and user roles."""
        self.access = []
        self.roles = []

    def is_one(self, role):
        """Check to see if a user is in a role."""
        return role in self.roles

    def is_any(self, roles):
        """Check to see if a user is in any of the listed roles."""
        for role in roles:
            if role in self.roles:
                return True
        return False

    def is_all(self, roles):
        """Check to see if a user is in all of the listed roles."""
        for role in roles:
            if role not in self.roles:
                return False
        return True

    def has_access(self, class_name='*', action_name='*'):
        """Tells whether or not to allow access to a class/action combination.
        """
        for info in self.access:
            match1 = (info['class']  == class_name  or info['class']  == '*')
            match2 = (info['action'] == action_name or info['action'] == '*')
            if match1 and match2:
                # Class and action matched, so return the flag.
                return bool(info['flag'])

        # No matching params, so deny.
        return False
