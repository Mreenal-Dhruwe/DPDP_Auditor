import sentry_sdk
from mixpanel import Mixpanel

mp = Mixpanel("project-token")


def on_signup(user):
    mp.track(user.id, "Signed Up", {"$email": user.email, "$phone": user.phone})
    sentry_sdk.set_user({"id": user.id, "email": user.email, "ip_address": user.last_ip})
