from crm.api import OUTBOX_ENABLED_ENV, outbox_enabled


def test_outbox_is_off_until_the_desktop_overlay_enables_it():
    assert not outbox_enabled({})
    assert not outbox_enabled({OUTBOX_ENABLED_ENV: 'yes'})
    assert outbox_enabled({OUTBOX_ENABLED_ENV: 'true'})
    assert outbox_enabled({OUTBOX_ENABLED_ENV: 'TRUE'})
