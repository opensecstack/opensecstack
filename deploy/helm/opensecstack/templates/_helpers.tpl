{{/*
Expand the chart name.
*/}}
{{- define "opensecstack.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full release name (release-chart), capped at 63 chars.
*/}}
{{- define "opensecstack.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels added to every resource.
*/}}
{{- define "opensecstack.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: opensecstack
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels for a given component.
Usage: include "opensecstack.selectorLabels" (dict "component" "apiguard")
*/}}
{{- define "opensecstack.selectorLabels" -}}
app: {{ .component }}
{{- end }}

{{/*
Resolve an image reference honouring global.imageRegistry.
Usage: include "opensecstack.image" (dict "repository" "ghcr.io/opensecstack/apiguard" "tag" "latest" "global" .Values.global)
When global.imageRegistry is set the repository's built-in registry prefix is
replaced so all images are pulled from the same registry mirror.
*/}}
{{- define "opensecstack.image" -}}
{{- $repo := .repository -}}
{{- $tag  := .tag | default "latest" -}}
{{- if and .global .global.imageRegistry (ne .global.imageRegistry "") -}}
  {{- $parts := splitList "/" $repo -}}
  {{- if gt (len $parts) 2 -}}
    {{/* strip the leading registry segment */}}
    {{- $withoutReg := rest $parts | join "/" -}}
    {{- printf "%s/%s:%s" .global.imageRegistry $withoutReg $tag -}}
  {{- else -}}
    {{- printf "%s/%s:%s" .global.imageRegistry $repo $tag -}}
  {{- end -}}
{{- else -}}
  {{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/*
Resolve imagePullPolicy: prefer component-level override, fall back to global.
Usage: include "opensecstack.pullPolicy" (dict "global" .Values.global "pullPolicy" .Values.apiguard.image.pullPolicy)
*/}}
{{- define "opensecstack.pullPolicy" -}}
{{- .pullPolicy | default .global.imagePullPolicy | default "IfNotPresent" -}}
{{- end }}
