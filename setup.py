from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='scoutr',
    description='Generic full access control API for talking to Dynamo via API Gateway',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='dynamo nosql api rbac',
    url='https://github.com/GESkunkworks/scoutr',
    use_scm_version=True,
    author='Michael Palmer',
    packages=find_packages(),
    setup_requires=[
        'setuptools_scm>=3.3.3,<4.2.0'
    ],
    install_requires=[
        # 'boto3>=1.12.39,<1.17.0',
        'mypy',
        # 'boto3-stubs[dynamodb]'
    ],
    extras_require={
        'flask': [
            'Flask-API>=1.1,<3.0',
            'Flask~=1.1.1',
            'simplejson>=3.16,<3.18'
        ],
        'dynamo': [
            'boto3~=1.14.37',
            'botocore~=1.17.37',
            'boto3-stubs[dynamodb]'
        ],
        'firestore': [
            'google~=3.0.0',
            'firebase-admin~=4.4.0',
        ],
        'mongo': [
            'pymongo~=3.11.0'
        ],
        'docs': [
            'mkdocs',
            'mkdocs-material'
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Development Status :: 5 - Production/Stable'
    ]
)
