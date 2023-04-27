FROM python:3.9
RUN pip3 install parsuite
ENTRYPOINT ["parsuite"]
CMD ["--help"]
