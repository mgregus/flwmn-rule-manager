from setuptools import setup, find_packages


setup(
    name="rule-manager",
    version="1.0.0",
    author="MGREGUS",
    description="Group of python CLI scripts to manage rule-sources on flowmon collector appliance instance.",
    url="https://github.com/mgregus/flwmn-rule-manager",
    packages=find_packages(),
    install_requires=[
        'argcomplete==3.2.2',
        'certifi==2024.2.2',
        'cffi==1.16.0',
        'charset-normalizer==3.3.2',
        'click==8.1.7',
        'colorama==0.4.6',
        'filelock==3.13.1',
        'idna==3.6',
        'Jinja2==3.1.3',
        'lxml==5.1.0',
        'Mako==1.3.2',
        'Markdown==3.6',
        'MarkupSafe==2.1.5',
        'packaging==23.2',
        'pdoc==14.4.0',
        'pdoc3==0.10.0',
        'pycparser==2.21',
        'pycurl==7.45.2',
        'Pygments==2.17.2',
        'PyYAML==6.0.1',
        'requests==2.31.0',
        'setuptools==69.0.3',
        'six==1.16.0',
        'typing_extensions==4.9.0',
        'urllib3==2.2.1'
    ],
    python_requires='>=3.6',
    keywords='suricata, ET/OPEN, metadata, rulesets, stats',
    project_urls={
        'Documentation': 'https://github.com/mgregus/flwmn-rule-manager/docs',
        'Source': 'https://github.com/mgregus/flwmn-rule-manager',
    },
)