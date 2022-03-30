from parsuite import helpers
from IPython import embed

def test_SortableURL_new():
    url = helpers.SortableURL('https', 'www.test.com', 80)
    assert isinstance(url, helpers.SortableURL)

def test_SortableURL_sorting():
    u1 = helpers.SortableURL(None, '192.168.86.1', None)
    u2 = helpers.SortableURL(None, '192.168.86.2', None)
    u3 = helpers.SortableURL(None, '192.168.86.3', None)

    urls = sorted([u3, u1, u2])

    locs = locals()
    for n in range(1, 4):
        assert locs['u'+str(n)] == urls[n-1]
