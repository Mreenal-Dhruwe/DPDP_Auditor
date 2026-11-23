import sentry_sdk
from mixpanel import Mixpanel

mp = Mixpanel("project-token")


def on_signup(user):
    mp.track(user.public_id, "Signed Up", {"plan": user.plan, "city_tier": user.city_tier})
    sentry_sdk.set_user({"id": user.public_id})
