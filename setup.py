import setuptools

# Read README.md as a variable to pass as the package's long
# description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setuptools.setup(
    name='parsuite',
    version='0.0.0',
    author='Justin Angel',
    author_email='justin@arch4ngel.ninja',
    description='A framework to parse common things.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/arch4ngel/parsuite',
    include_package_data=True,
    package_dir={'':'src'},
    packages=setuptools.find_packages(where='src'),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.9',
    scripts=['parsuite'],
    # package_data={'parsuite.datasets':['*.txt', '*.yaml', '*.xml']},
    install_requires=[
        'django',
        'tabulate',
        'lxml',
        'colored==1.3.93',
        'termcolor',
        'IPython',
        'django',
        'tabulate',
        'lxml',
        'colored==1.3.93',
        'termcolor',
        'IPython',
        'nessrest',
        'jsbeautifier',
        'netinfo',
        'netaddr==0.7.19',
        'neo4j>=4.2.1',
        'publicsuffix2',
        'python-slugify']
)
