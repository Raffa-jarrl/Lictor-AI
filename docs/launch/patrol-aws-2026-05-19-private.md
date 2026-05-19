# Patrol — AWS access-key exposure (PRIVATE)

**Scanned at:** 2026-05-19 08:30 UTC
**Candidates inspected:** 300
**Confirmed exposures:** 48
  (with paired secret: 38)

| Repo | Path | ★ | Pushed | AKIA (redacted) | Paired secret? | File |
|---|---|---|---|---|---|---|
| `numenta/nupic-legacy` | `.travis.yml` | 6353 | 2024-12-03 | `AKIAIGHY…OWNQ` | **YES** | [link](https://github.com/numenta/nupic-legacy/blob/7281482def2a96fbda663e6c39e8351a1886dec7/.travis.yml) |
| `DataDog/managed-kubernetes-auditing-toolkit` | `examples/demo-cluster/terraform/secrets.tf` | 378 | 2026-05-07 | `AKIAZ3MS…W5FG` | **YES** | [link](https://github.com/DataDog/managed-kubernetes-auditing-toolkit/blob/9fa7ff53e27b010009e90359ddbd438429277135/examples/demo-cluster/terraform/secrets.tf) |
| `zenml-io/mlstacks` | `aws-minimal/variables.tf` | 255 | 2024-10-09 | `AKIAJX7X…7X7X` | no | [link](https://github.com/zenml-io/mlstacks/blob/59b7ce6f6270a9bde8c006da70f959073ab96811/aws-minimal/variables.tf) |
| `MyRobotLab/myrobotlab` | `.travis.yml` | 254 | 2025-11-03 | `AKIAJ6CQ…KNXA` | no | [link](https://github.com/MyRobotLab/myrobotlab/blob/3eab17db7faae8d7c45ae352dd9ba0edb1dadc67/.travis.yml) |
| `gashok13193/DevOps-Docs` | `Terraform/modules/main.tf` | 181 | 2026-05-15 | `AKIAXEFU…L363` | **YES** | [link](https://github.com/gashok13193/DevOps-Docs/blob/bb041ffa0315d58d6ae10828d1d9184ca17d2c28/Terraform/modules/main.tf) |
| `asquarezone/TerraformZone` | `Dec17/HelloWorld/helloworld.tf` | 25 | 2025-01-22 | `AKIAJ7X3…RGVQ` | **YES** | [link](https://github.com/asquarezone/TerraformZone/blob/f97d19e8dfc133e9442759cfbe7669329bcf3347/Dec17/HelloWorld/helloworld.tf) |
| `SCK-SEAL-TEAM-One/shopping-cart` | `infrastructure/instance.tf` | 25 | 2025-04-30 | `AKIA2LXJ…EETJ` | **YES** | [link](https://github.com/SCK-SEAL-TEAM-One/shopping-cart/blob/b15bf9112143c6f6f0bcfb9714794f4b105abcf3/infrastructure/instance.tf) |
| `manoj7894/Devops-AWS-2024` | `Terraform/Terraform-data/AMI/var.tf` | 7 | 2026-04-20 | `AKIATWS3…4F5U` | **YES** | [link](https://github.com/manoj7894/Devops-AWS-2024/blob/30d26be0ff3d54b10df9920582ff00bda2251e6a/Terraform/Terraform-data/AMI/var.tf) |
| `shalloe99/TaxAI` | `.env` | 3 | 2025-02-16 | `AKIAV55X…TF22` | **YES** | [link](https://github.com/shalloe99/TaxAI/blob/5eddce75e43758a6d21b8b94d6d16f721e846481/.env) |
| `Sourcesiri-Kamelot/SoulCoreHub` | `.env` | 3 | 2025-12-22 | `AKIA2FXA…PZB2` | **YES** | [link](https://github.com/Sourcesiri-Kamelot/SoulCoreHub/blob/7aef746e585e8814041c4c1f3bc39a19c1203e7c/.env) |
| `supersorbet/non-kyc-uniswap-interface` | `.env` | 2 | 2025-10-27 | `AKIAYJJW…ATHN` | **YES** | [link](https://github.com/supersorbet/non-kyc-uniswap-interface/blob/d3293e3c922b364febddee8fdb6a29937ef0b521/.env) |
| `alexelyvinsky/Bender` | `.env` | 2 | 2024-09-12 | `AKIAQAHA…3DMY` | **YES** | [link](https://github.com/alexelyvinsky/Bender/blob/8fb6cf2dedf0d66dd099d493c3d129c3b762be02/.env) |
| `max-de-bug/feather-app` | `.env` | 2 | 2025-12-27 | `AKIA6G75…ZXSE` | **YES** | [link](https://github.com/max-de-bug/feather-app/blob/b62420a823434da38eccec6719fe09220655a739/.env) |
| `Acodehacked/PORUKARA` | `.env` | 2 | 2025-08-01 | `AKIARAWL…QG4L` | **YES** | [link](https://github.com/Acodehacked/PORUKARA/blob/d93b8786e54de0e0ebeb508663408804d9dd2d32/.env) |
| `330012/GDSD-Team6-Fall2025` | `.env` | 2 | 2026-03-26 | `AKIASNTH…4F4K` | **YES** | [link](https://github.com/330012/GDSD-Team6-Fall2025/blob/f9e8d2ccbb85edbc6fcc9647068640353583b16c/.env) |
| `Mawruth/Mwrooth-API-old-` | `.env` | 2 | 2024-05-24 | `AKIAUDSD…TWQ4` | **YES** | [link](https://github.com/Mawruth/Mwrooth-API-old-/blob/f7c77ad3f929c5beb5ad02a938e5afa1de0f0ddc/.env) |
| `kovvurusubbu/pavan` | `Teeraform/mongo.tf` | 1 | 2026-02-21 | `AKIA2SRV…EAOA` | **YES** | [link](https://github.com/kovvurusubbu/pavan/blob/8c763f10a77ddc09a551e0906c4ab29679578f03/Teeraform/mongo.tf) |
| `kashwin777/Deloite` | `TF-AWS/TF-own-module-VPC/module-vpc/versions.tf` | 1 | 2025-07-14 | `AKIA4SYA…SEWX` | **YES** | [link](https://github.com/kashwin777/Deloite/blob/fc3c5100c8c2d5b46c4cc33a1ae27e916c5329e5/TF-AWS/TF-own-module-VPC/module-vpc/versions.tf) |
| `OX-Security-Demo/Multi-currency-management` | `.env` | 1 | 2026-05-18 | `AKIAX7EG…QGWH` | **YES** | [link](https://github.com/OX-Security-Demo/Multi-currency-management/blob/c4582e5aa0920a139c145916400cb6b813505b00/.env) |
| `CrashBytes/tutorial-ai-model-monitoring` | `.env` | 1 | 2026-05-05 | `AKIA3J3U…JXOS` | **YES** | [link](https://github.com/CrashBytes/tutorial-ai-model-monitoring/blob/d47d50f276da46d0bfe8f846a8a54ae76ce709f5/.env) |
| `X103703/ans` | `var.tf` | 0 | 2024-08-01 | `AKIA3Y2A…64SH` | **YES** | [link](https://github.com/X103703/ans/blob/f395094500f05317d33b9f392971f38dc4385e5e/var.tf) |
| `tim-wiz/ci-demo-tim` | `bucket.tf` | 0 | 2025-11-10 | `AKIAQEFZ…PPPZ` | **YES** | [link](https://github.com/tim-wiz/ci-demo-tim/blob/b47eff54c314164030ecaba4ef65b1106c4f1e02/bucket.tf) |
| `GauravBole/phiter` | `terraform/providers.tf` | 0 | 2026-05-05 | `AKIAVTKQ…FIMU` | **YES** | [link](https://github.com/GauravBole/phiter/blob/74c885485e1dfba4bbd09c55c9f2eafc6897d8aa/terraform/providers.tf) |
| `Akbar335/Terraform-AWS-EC2-SAI` | `providers.tf` | 0 | 2025-08-20 | `AKIA3WUY…24HO` | **YES** | [link](https://github.com/Akbar335/Terraform-AWS-EC2-SAI/blob/f83e9200b27360e974172cdcd75b3d0e0c9cbdcb/providers.tf) |
| `saikishore789/terraform` | `splat_example/splat_iamuser.tf` | 0 | 2026-02-14 | `AKIAQKED…JUUD` | **YES** | [link](https://github.com/saikishore789/terraform/blob/05bacef05d831d87ae95dbdc391a1e3f8e698f76/splat_example/splat_iamuser.tf) |
| `Tejas20002/labs-terraform` | `EC2/ec2.tf` | 0 | 2024-12-20 | `AKIASZVL…2FJ7` | **YES** | [link](https://github.com/Tejas20002/labs-terraform/blob/061371bf1895018505fffb2c1c29a6b0c0a1b331/EC2/ec2.tf) |
| `sriramkausik/Ansible_Infra` | `varaiable.tf` | 0 | 2025-09-15 | `AKIA4MTW…XC4P` | **YES** | [link](https://github.com/sriramkausik/Ansible_Infra/blob/76c39d13d4b1e544f245310aaa7db23d6e403ea5/varaiable.tf) |
| `sathyas1905/Ansible_project_new` | `varaiable.tf` | 0 | 2025-05-26 | `AKIATC6A…3UH5` | **YES** | [link](https://github.com/sathyas1905/Ansible_project_new/blob/a2d74576bc53d750071b625545ce4679c0232800/varaiable.tf) |
| `muthuri-dev/terraform-k8s` | `using-modules/1-variables.tf` | 0 | 2025-09-29 | `AKIAVIOZ…V5E7` | **YES** | [link](https://github.com/muthuri-dev/terraform-k8s/blob/1912855343d29c76aab544766a1b1d4d5101b099/using-modules/1-variables.tf) |
| `Vikas5988/terraform-learning-backup` | `terraform-module/providers.tf` | 0 | 2025-04-05 | `AKIAZI2L…4HOW` | **YES** | [link](https://github.com/Vikas5988/terraform-learning-backup/blob/d2c5e962bfc73634fff8f3bf32785d7556270f78/terraform-module/providers.tf) |
| `arroyocreativa/senales_backend` | `.env` | 0 | 2024-08-01 | `AKIA2THR…5TUM` | **YES** | [link](https://github.com/arroyocreativa/senales_backend/blob/89e6d1e65d69171b2441675490aad9ade3ad1366/.env) |
| `Intrinsic-network/interface` | `.env` | 0 | 2025-12-12 | `AKIAYJJW…ATHN` | **YES** | [link](https://github.com/Intrinsic-network/interface/blob/ed32cb3b6d81ea05940f0ba32e868c424fc5cc28/.env) |
| `Diibro/clickrwanda-client` | `.env` | 0 | 2025-07-12 | `AKIA6ODV…XM4L` | **YES** | [link](https://github.com/Diibro/clickrwanda-client/blob/364fd8b72a3219c2dc66628c90e69c217128fd57/.env) |
| `mirmeherbanali/aihubbe` | `.env` | 0 | 2026-04-03 | `AKIAR3FL…PYI7` | **YES** | [link](https://github.com/mirmeherbanali/aihubbe/blob/72bbe5a36f34a2e255d210f7ab80d0e62670882a/.env) |
| `Kundan20202/Converter` | `.env` | 0 | 2025-04-06 | `AKIASOCZ…U7WN` | **YES** | [link](https://github.com/Kundan20202/Converter/blob/538791cc49ea9d566b7cca0c0b7e6b9960944012/.env) |
| `NewProject01st/project` | `.env` | 0 | 2024-08-26 | `AKIA6GBM…3YAX` | **YES** | [link](https://github.com/NewProject01st/project/blob/e48bc65646160d604828b7f9b2457428de65ce6b/.env) |
| `optymoneydev/optymoney_laravel_admin` | `.env` | 0 | 2024-06-05 | `AKIAWQE2…GZOL` | **YES** | [link](https://github.com/optymoneydev/optymoney_laravel_admin/blob/6be3827ebff519d34c6c61062fd9706b07a97fac/.env) |
| `4RL3N/Projeto-if977-Eng.Software` | `.env` | 0 | 2024-10-09 | `AKIASFUI…A3F2` | **YES** | [link](https://github.com/4RL3N/Projeto-if977-Eng.Software/blob/07d961cd88bd7caba26a642fe8c1c63effbb1945/.env) |
| `williamsAdebola/skills-introduction-to-secret-scanning` | `cre.yml` | 0 | 2025-06-12 | `AKIAQYLP…Z56B` | **YES** | [link](https://github.com/williamsAdebola/skills-introduction-to-secret-scanning/blob/c8d85c26e7dd3b961c83c3bf6cb97742962466d7/cre.yml) |
| `akkki98/skills-introduction-to-secret-scanning3` | `cred.yml` | 0 | 2026-01-05 | `AKIAQYLP…Z56B` | **YES** | [link](https://github.com/akkki98/skills-introduction-to-secret-scanning3/blob/5f840a87ff2dd4856cb672a32b681596d7106b54/cred.yml) |
| `Thiru4545/Terraform-Basics` | `Provider.tf` | 0 | 2025-06-03 | `AKIAZ24I…324F` | no | [link](https://github.com/Thiru4545/Terraform-Basics/blob/ef9488069c3466face80860e893399213f0fd426/Provider.tf) |
| `prashanthgowdaN/my-terraform-repo` | `modules/EC2_Instance/providers.tf` | 0 | 2026-03-13 | `AKIAVFIW…7KCQ` | no | [link](https://github.com/prashanthgowdaN/my-terraform-repo/blob/d56a88feeed7857459580ae2a2714652e561fa60/modules/EC2_Instance/providers.tf) |
| `ashenglow/infra-template-goorm` | `terraform/generated/aws/iam/iam_access_key.tf` | 0 | 2025-06-26 | `AKIAYDWH…P756` | no | [link](https://github.com/ashenglow/infra-template-goorm/blob/46e21285f55495ec0c21d2e385971b15ea7ed429/terraform/generated/aws/iam/iam_access_key.tf) |
| `FriendFactory/open-platform` | `platform/iam/iam.tf` | 0 | 2025-06-23 | `AKIA2QUH…YVIE` | no | [link](https://github.com/FriendFactory/open-platform/blob/2f4b0d846c85cf176c7897d0fc370c6d0f8f616d/platform/iam/iam.tf) |
| `essa-khan/GitHoundSeededSecrets` | `aws_access_key.env` | 0 | 2025-04-06 | `AKIA1234…CDEF` | no | [link](https://github.com/essa-khan/GitHoundSeededSecrets/blob/eacd74f15eabfd8c8c6c487ef4577c17976d9e89/aws_access_key.env) |
| `gim-dev-team/test-corentin` | `aws.yml` | 0 | 2024-10-08 | `AKIA2PFU…SZ4M` | no | [link](https://github.com/gim-dev-team/test-corentin/blob/724a22ec5355e74fc0a769aa01ee17236feae55a/aws.yml) |
| `priyam930/Ansible_Training` | `AWS_EC2.yml` | 0 | 2024-12-09 | `AKIA2YIC…YPPB` | no | [link](https://github.com/priyam930/Ansible_Training/blob/0c4b88fa1b731d53401040d995964d8ccba3094c/AWS_EC2.yml) |
| `SlootSantos/ec-store-module` | `.travis.yml` | 0 | 2026-02-11 | `AKIAJFMT…FVXA` | no | [link](https://github.com/SlootSantos/ec-store-module/blob/418987d851ea7128e0ec9ddc3f1e46e03e45511d/.travis.yml) |