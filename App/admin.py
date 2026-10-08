from django.contrib import admin

from App.models import  FilterPreset, GitHubUpdate, Tactic, Technique, ThreatActor, ThreatActors, ThreatFeed, ThreatProfile, ThreatRecord, TrendingData

# Register your models here.
admin.site.register(ThreatRecord)
# admin.site.register(ThreatProfile)
admin.site.register(ThreatFeed)
admin.site.register(TrendingData)
admin.site.register(FilterPreset)
# admin.site.register(ThreatActor)
admin.site.register(GitHubUpdate)
# admin.site.register(MitreAttack)
admin.site.register(Technique)
admin.site.register(Tactic)
admin.site.register(ThreatActors)
# admin.site.register(ActorGroupMatch)



