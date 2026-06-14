{{/*
Common helpers — Bitnami-style naming + label conventions.
*/}}

{{- define "vertguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vertguard.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "vertguard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vertguard.labels" -}}
helm.sh/chart: {{ include "vertguard.chart" . }}
{{ include "vertguard.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: opensecstack
{{- end -}}

{{- define "vertguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vertguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vertguard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "vertguard.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve image tag — fall back to .Chart.AppVersion when not pinned.
*/}}
{{- define "vertguard.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "vertguard.imagePullSecrets" -}}
{{- with .Values.image.pullSecrets -}}
imagePullSecrets:
{{- range . }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end -}}

{{/*
Database host: prefer the embedded Bitnami postgresql primary service
when enabled; otherwise use the user-supplied config.db.host.
*/}}
{{- define "vertguard.databaseHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "%s-postgresql" .Release.Name -}}
{{- else -}}
{{- .Values.config.db.host -}}
{{- end -}}
{{- end -}}

{{/*
Resolved name of the secret holding sensitive env values.
*/}}
{{- define "vertguard.secretName" -}}
{{- if .Values.existingSecret -}}
{{- .Values.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "vertguard.fullname" .) -}}
{{- end -}}
{{- end -}}
