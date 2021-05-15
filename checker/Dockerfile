FROM python:3.9

# Create user
RUN useradd -ms /bin/bash -u 1000 checker

USER checker
WORKDIR /checker

# Install all required dependencies for the checker.
COPY ./requirements.txt /checker/requirements.txt
RUN pip3 install -r requirements.txt

# Copy all files into the container.
COPY . /checker/


ENTRYPOINT [ "/home/checker/.local/bin/gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]
