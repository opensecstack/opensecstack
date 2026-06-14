{{/*
Common helpers for the vertguard-ml subchart. Mirrors the parent's
naming so operators recognise both charts at a glance.
*/}}

{{- define "vertguard-ml.name" -}}
{{- default "vertguard-ml" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vertguard-ml.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "vertguard-ml.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vertguard-ml.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vertguard-ml.labels" -}}
helm.sh/chart: {{ include "vertguard-ml.chart" . }}
{{ include "vertguard-ml.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: ml-inference
app.kubernetes.io/part-of: opensecstack
{{- end -}}

{{- define "vertguard-ml.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vertguard-ml.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vertguard-ml.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vertguard-ml.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "vertguard-ml.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "vertguard-ml.imagePullSecrets" -}}
{{- with .Values.image.pullSecrets -}}
imagePullSecrets:
{{- range . }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end -}}

{{- define "vertguard-ml.secretName" -}}
{{- if .Values.secret.existingSecret -}}
{{- .Values.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "vertguard-ml.fullname" .) -}}
{{- end -}}
{{- end -}}
