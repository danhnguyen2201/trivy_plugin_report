# trivy-plugin-report

# scan imagesimages
trivy image -f json images | trivy report -o name.xlsx
