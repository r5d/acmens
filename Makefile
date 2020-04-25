#
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright © 2020 rsiddharth <s@ricketyspace.net>
#

develop:
	@python3 setup.py develop
.PHONY: develop

build:
	@python3 setup.py sdist bdist_wheel
.PHONY: build

upload:
	@twine upload -r pypi -s -i \
		'1534 126D 8C8E AD29 EDD9  1396 6BE9 3D8B F866 4377' \
		dist/*.tar.gz
	@twine upload -r pypi -s -i \
		'1534 126D 8C8E AD29 EDD9  1396 6BE9 3D8B F866 4377' \
		dist/*.whl
.PHONY: upload

clean:
	@python3 setup.py clean
	@rm -rf build/ dist/ *.egg-info __pycache__/
	@find . -name '*.pyc' -exec rm -f {} +
.PHONY: clean
