import { KNOWLEDGE_BASE } from './intel.js';

export function ResourcesPage() {
    return {
      conceptModal: false,
      currentConcept: '',
      conceptContent: '',
      loadingConcept: false,
      conceptError: '',
      conceptAnimations: {},
      knowledgeBase: KNOWLEDGE_BASE,
      complexityFilter: 'All',
      categoryFilter: 'All',
      
      get filteredKnowledgeBase() {
        let items = this.knowledgeBase;

        // Filter by Category (from URL or selection)
        if (this.categoryFilter !== 'All') {
            if (this.categoryFilter === 'Security') {
                // "Knowledge Base" view - Security focused
                items = items.filter(item => 
                    item.tags.includes('Threat Intel') || 
                    item.tags.includes('Cloud Security') || 
                    item.tags.includes('Malware') ||
                    item.tags.includes('Security')
                );
            } else {
                // Generic tag filter
                items = items.filter(item => item.tags.includes(this.categoryFilter));
            }
        }

        // Filter by Complexity (dropdown)
        if (this.complexityFilter !== 'All') {
            items = items.filter(item => item.complexity === this.complexityFilter);
        }
        
        return items;
      },

      get pageTitle() {
          return this.categoryFilter === 'Security' ? 'Knowledge Base' : 'All Concepts';
      },

      init() {
        // Initialize random pulse animations for DNS concepts
        this.initRandomPulseAnimations();

        // Check for params in URL
        const urlParams = new URLSearchParams(window.location.search);
        
        const category = urlParams.get('category');
        if (category) {
            this.categoryFilter = category;
        }

        const concept = urlParams.get('concept');
        if (concept) {
            // Wait a tick for Alpine to initialize
            this.$nextTick(() => {
                this.showConcept(decodeURIComponent(concept));
            });
        }
      },
      
      initRandomPulseAnimations() {
        const concepts = [
          'A Record', 'AAAA Record', 'CNAME Record', 'MX Record', 
          'TXT Record', 'NS Record', 'PTR Record', 'SRV Record', 'CAA Record',
          'SPF', 'DKIM', 'DMARC'
        ];
        
        // Randomly select 3-4 concepts to pulse
        const numToPulse = Math.floor(Math.random() * 2) + 3; // 3 or 4 concepts
        const shuffled = concepts.sort(() => 0.5 - Math.random());
        const selectedConcepts = shuffled.slice(0, numToPulse);
        
        // Initialize all concepts as not pulsing
        concepts.forEach(concept => {
          this.conceptAnimations[concept] = false;
        });
        
        // Add staggered pulse animations
        selectedConcepts.forEach((concept, index) => {
          setTimeout(() => {
            this.conceptAnimations[concept] = true;
            
            // Stop pulsing after user has been on page for a while (15 seconds)
            setTimeout(() => {
              this.conceptAnimations[concept] = false;
            }, 15000);
          }, index * 800); // Stagger the start times by 800ms
        });
      },
      
      showConcept(conceptName) {
        this.currentConcept = conceptName;
        this.conceptModal = true;
        this.loadConcept(conceptName);
      },
      
      closeConcept() {
        this.conceptModal = false;
        this.conceptContent = '';
        this.conceptError = '';
        this.currentConcept = '';
      },
      
      async loadConcept(conceptName) {
        this.loadingConcept = true;
        this.conceptError = '';
        this.conceptContent = '';
        
        try {
          // Check if it's in our Knowledge Base
          const kbItem = this.knowledgeBase.find(item => item.title === conceptName);
          
          if (kbItem) {
             await new Promise(resolve => setTimeout(resolve, 300)); // Small UI delay
             this.conceptContent = kbItem.content;
          } else {
             this.conceptError = 'Concept not found.';
          }
          
        } catch (error) {
          this.conceptError = 'Failed to load detailed explanation. Please try again.';
        } finally {
          this.loadingConcept = false;
        }
      }
    };
  };
