import os, unittest

def skip_if_dependabot_pr(func):
    """Decorator for skipping a test method if it's a Dependabot PR."""
    dependabot_pr = os.getenv('DEPENDABOT_PR')
    if dependabot_pr is not None and int(dependabot_pr):
        return unittest.skip("Dependabot PR")(func)
    else:
        return func
    
if __name__ == '__main__':
    pass