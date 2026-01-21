# trivy-plugin-report

# install plugins

trivy plugin install https://github.com/danhnguyen2201/trivy-plugin-report/releases/download/0.1.0/trivy-plugin-report_0.1.0_linux_amd64.tar.gz

# scan images xlsx
trivy image -f json images | trivy report -o name.xlsx

# scan images pdf
trivy image -f json images | trivy report -o name.pdf

# scan images pdf
trivy image -f json images | trivy report -o name.csv
