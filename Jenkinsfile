pipeline {
  agent any
  parameters {
    string(name: 'BRANCH', defaultValue: 'main', description: 'Branch to build')
  }
  stages {
    stage('Checkout') {
      steps { 
        git branch: "${params.BRANCH}", url: 'https://github.com/Adw0rm-sec/VISTA.git'
      }
    }
    stage('Build') {
      steps {
        sh 'mvn -B clean package'   // run Maven as repo expects
      }
    }
    stage('Archive') {
      steps { archiveArtifacts artifacts: 'target/*.jar', allowEmptyArchive: false }
    }
  }
}
